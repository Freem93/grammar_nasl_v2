#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58951);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/12 02:12:32 $");

  script_name(english:"Comodo Internet Security Installed");
  script_summary(english:"Checks for Comodo Internet Security");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running an internet security application.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Comodo Internet Security, an internet
security application for Windows.");
  script_set_attribute(attribute:"see_also", value:"http://www.comodo.com/home/internet-security/free-internet-security.php");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("audit.inc");
include("install_func.inc");

port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
item = "SOFTWARE\ComodoGroup\CDI\1\InstallProductPath";
path = get_registry_value(handle:handle, item:item);
RegCloseKey(handle:handle);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, 'Comodo Internet Security');
}
else close_registry(close:FALSE);

version = NULL;
share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
dat = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\cfpver.dat", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:dat,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

version = NULL;
if (!isnull(fh))
{
  fsize = GetFileSize(handle:fh);
  if (fsize > 10240) fsize = 10240;
  if (fsize)
  {
    data = ReadFile(handle:fh, length:fsize, offset:0);
    CloseFile(handle:fh);
    if (!isnull(data))
    {
      data = chomp(data);
      if (data =~ '^[0-9\\.]+$')
      {
        version = data;
      }
    }
  }
  CloseFile(handle:fh);
}
NetUseDel();

if (isnull(version))
  audit(AUDIT_VER_FAIL, (share - '$')+':'+dat);

set_kb_item(name:'SMB/Comodo Internet Security/Path', value:path);
set_kb_item(name:'SMB/Comodo Internet Security/Version', value:version);

register_install(
  app_name:'Comodo Internet Security',
  path:path,
  version:version);

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version +
    '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
