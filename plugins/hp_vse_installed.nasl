#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(53623);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/07 18:43:41 $");

  script_name(english:"HP Virtual Server Environment Detection");
  script_summary(english:"Checks for HP Virtual Server Environment");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host contains a virtual infrastructure environment.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host contains HP Virtual Server Environment, an
application for managing virtual server infrastructures.");

  script_set_attribute(attribute:"see_also", value:"http://h20338.www2.hp.com/enterprise/cache/258348-0-0-14-121.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:'cpe', value:"cpe:/a:hp:virtual_server_environment");
  script_end_attributes();

  script_family(english:"Windows");
  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

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

get_kb_item_or_exit('SMB/Registry/Enumerated');

name   = kb_smb_name();
port   = kb_smb_transport();

login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, 'Can\'t connect to IPC$ share.');
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, 'Can\'t connect to the remote registry.');
}

path = NULL;
key = 'SOFTWARE\\Hewlett-Packard\\Virtual Server Environment';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:'InstallPath');
  if (!isnull(item))
  {
    path = item[1];
  }
  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (isnull(path))
{
  NetUseDel();
  exit(0, 'HP Virtual Server Environment isn\'t installed on the remote host.');
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
exe   = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\uninstallvse.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, 'Can\'t connect to '+share+' share.');
}

version = NULL;
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
  exit(1, 'Couldn\'t open '+path+'\\uninstallvse.exe');
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(ver)) exit(1, 'Couldn\'t get the version of '+path+'\\uninstallvse.exe');

version = join(sep:'.', ver);
version_ui = ver[0] + '.' + ver[1];
set_kb_item(name:'SMB/HP_VSE/Version', value:version);
set_kb_item(name:'SMB/HP_VSE/Version_UI', value:version_ui);
set_kb_item(name:'SMB/HP_VSE/Path', value:path);

register_install(
  app_name:"HP Virtual Server Environment",
  path:path,
  version:version,
  display_version:version_ui);

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version_ui + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
