#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69801);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"Cisco IP Communicator Installed");
  script_summary(english:"Checks for Cisco IP Communicator");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has a softphone application installed.");
  script_set_attribute(attribute:"description", value:
"Cisco IP Communicator, a softphone application for Windows, is
installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/sw/voicesw/ps5475/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/06");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:ip_communicator");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

name   = kb_smb_name();
port   = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

appname = 'Cisco IP Communicator';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Cisco Systems, Inc.\Communicator\SoftPhoneData";
path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
close_registry(close:FALSE);

share = hotfix_path2share(path:path);
dll = ereg_replace(pattern:'^[A-Za-z]:(.*)', string:path, replace:"\1\sfb.dll");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (isnull(fh))
{
  NetUseDel();
  audit(AUDIT_UNINST, appname);
}

ver = GetProductVersion(handle:fh);
if ("," >< ver) ver = str_replace(find:",", replace:'.', string:ver);

CloseFile(handle:fh);
NetUseDel();

if (isnull(ver)) audit(AUDIT_VER_FAIL, path + "\sfb.dll");

kb_base = 'SMB/'+appname+'/';
set_kb_item(name:kb_base + 'Path', value:path);
set_kb_item(name:kb_base + 'Version', value:ver);

register_install(
  app_name:appname,
  path:path,
  version:ver,
  cpe:"cpe:/a:cisco:ip_communicator");

if (report_verbosity > 0)
{
  report +=
    '\n  Path    : ' + path +
    '\n  Version : ' + ver + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
