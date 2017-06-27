#
# (C) Tenable Network Security. Inc.
#

include('compat.inc');

if (description)
{
  script_id(57795);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_name(english:"Symantec pcAnywhere Installed");
  script_summary(english:"Checks for Symantec pcAnywhere");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has a remote access application installed.");
  script_set_attribute(attribute:"description", value:
"Symantec pcAnywhere, a remote access application, is installed on the
remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/pcanywhere");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:pcanywhere");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('smb_func.inc');
include("audit.inc");
include("install_func.inc");

get_kb_item('SMB/Registry/Enumerated');

# Connect to the appropriate share.
name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (rc != 1)
{
  NetUseDel();
  exit(1, 'Can\'t connect to IPC$ share.');
}

# Connect to the remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, 'Can\'t connect to the remote registry.');
}

path = NULL;
key = 'SOFTWARE\\Symantec\\pcAnywhere\\CurrentVersion\\System';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:'InstallDir');
  if (!isnull(item)) path = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, 'Symantec pcAnywhere is not installed on the remote host.');
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
exe   = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\WinAw32.exe', string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, 'Can\'t connect to '+share+' share.');
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
  exit(0, 'Couldn\'t open \''+(share-'$')+':'+exe+'\'.');
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(ver)) exit(1, 'Couldn\'t get the version of \''+(share-'$')+':'+exe+'\'.');

version = ver[0] + '.' + ver[1] + '.' + ver[2];
build = ver[3];

set_kb_item(name:'SMB/Symantec pcAnywhere/Version', value:version);
set_kb_item(name:'SMB/Symantec pcAnywhere/Path', value:path);
set_kb_item(name:'SMB/Symantec pcAnywhere/Build', value:build);

register_install(
  app_name:"Symantec pcAnywhere",
  path:path,
  version:version,
  extra:make_array("Build", build),
  cpe:"cpe:/a:symantec:pcanywhere");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + ' Build ' + build +
    '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
