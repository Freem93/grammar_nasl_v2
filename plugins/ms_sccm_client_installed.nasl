#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(55532);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_name(english:"Microsoft System Center Configuration Manager Client Installed");
  script_summary(english:"Checks for SCCM client");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has a management client application installed.");
  script_set_attribute(attribute:"description", value:
"The Microsoft System Center Configuration Manager client, a management
system client, is installed on the remote Windows host.");

  script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/systemcenter/en/us/configuration-manager.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:sccm_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('misc_func.inc');
include("audit.inc");
include("install_func.inc");

login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();
port   = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

path = NULL;

key = 'SOFTWARE\\Microsoft\\CCM';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:'TempDir');
  if (!isnull(item)) path = item[1];
  if ('\\Temp\\' >< path) path = path - '\\Temp\\';

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, 'Microsoft SCCM client is not installed on the remote host.');
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
exe   = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\CcmExec.exe', string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  exit(1, 'Couldn\'t open \''+path+'\\CcmExec.exe\'.');
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(ver))
{
  exit(1, 'Couldn\'t get the version number from \''+path+'\\CcmExec.exe\'.');
}

version = join(ver, sep:'.');
set_kb_item(name:'SMB/Microsoft SCCM Client/Path', value:path);
set_kb_item(name:'SMB/Microsoft SCCM Client/Version', value:version);

register_install(
  app_name:"Microsoft System Center Configuration Manager Client",
  path:path,
  version:version,
  cpe:"x-cpe:/a:microsoft:sccm_client");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
