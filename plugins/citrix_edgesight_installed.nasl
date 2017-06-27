#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55473);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/10 19:18:33 $");

  script_name(english:"Citrix EdgeSight for Load Testing Detection");
  script_summary(english:"Checks for Citrix EdgeSight for Load Testing");

  script_set_attribute(attribute:"synopsis", value:
"There is a system and network monitoring application installed on the
remote host.");
  script_set_attribute(attribute:"description", value:
"Citrix EdgeSight for Load Testing, a system and network monitoring
application, is installed on the remote Windows host.");
  # https://web.archive.org/web/20110804045821/http://www.cns-service.com/citrix/citrix-edgesight.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1b89a45");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:edgesight");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

name   = kb_smb_name();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();
port   = kb_smb_transport();




if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (rc != 1)
{
  NetUseDel();
  exit(1, 'Can\'t connect to IPC$ share.');
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, 'Can\'t connect to the remote registry.');
}

path = NULL;

key = 'SOFTWARE\\Citrix\\Citrix EdgeSight for Load Testing';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:'RootDir');
  if (!isnull(item)) path = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, 'Citrix EdgeSight for Load Testing is not installed on the remote host.');
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
exe   = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\Controller.exe', string:path);
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
  exit(1, 'Couldn\'t open \''+path+'\\Controller.exe\'.');
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(ver))
{
  exit(1, 'Couldn\'t get the version number from \''+path+'\\Controller.exe\'.');
}

version = join(ver, sep:'.');
set_kb_item(name:'SMB/Citrix EdgeSight for Load Testing/Path', value:path);
set_kb_item(name:'SMB/Citrix EdgeSight for Load Testing/Version', value:version);

register_install(
  app_name:"Citrix EdgeSight for Load Testing",
  path:path,
  version:version,
  cpe:"cpe:/a:citrix:edgesight");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
