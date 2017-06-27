#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59717);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/11 15:27:45 $");

  script_name(english:"HP LoadRunner Detect");
  script_summary(english:"Checks for HP LoadRunner.");

  script_set_attribute(attribute:"synopsis", value:
"A software performance testing application is installed on the remote
Windows host.");
  script_set_attribute(attribute:"description", value:
"HP LoadRunner, an application for testing software performance, is
installed on the remote Windows host.");
  # http://www8.hp.com/us/en/software-solutions/loadrunner-load-testing/index.html?#.T-NBFStYuJc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcb9961d");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:loadrunner");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include("install_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');
app = 'HP LoadRunner';

port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
  close_registry();
  audit(AUDIT_REG_FAIL);
}
key = "SOFTWARE\Mercury Interactive\LoadRunner\CurrentVersion\Controller";
path = get_registry_value(handle:hklm, item:key);

if (isnull(path))
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

key = "SOFTWARE\Mercury Interactive\LoadRunner\CurrentVersion\Major";
reg_major = get_registry_value(handle:hklm, item:key);
key = "SOFTWARE\Mercury Interactive\LoadRunner\CurrentVersion\Minor";
reg_minor = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
dll = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\bin\lr_eng32.dll", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  close_registry();
  audit(AUDIT_SHARE_FAIL, share);
}

# Confirm that the file exists
fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  close_registry();
  audit(AUDIT_UNINST, app);
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);

NetUseDel();

if (isnull(ver)) audit(AUDIT_VER_FAIL, (share - '$')+':'+dll);
version = join(ver, sep:'.');

if (!isnull(reg_major) && !isnull(reg_minor))
  verui = reg_major + "." + reg_minor;
else
  verui = ver[0] + '.' + ver[1];

set_kb_item(name:'SMB/'+app+'/Path', value:path);
set_kb_item(name:'SMB/'+app+'/Version', value:version);
set_kb_item(name:'SMB/'+app+'/VersionUI', value:verui);
register_install(
  app_name:app,
  path:path,
  version:version,
  display_version:verui,
  cpe:"cpe:/a:hp:loadrunner");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + verui + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
