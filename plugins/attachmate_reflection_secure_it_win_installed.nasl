#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(55284);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/03 20:48:27 $");

  script_name(english:"Attachmate Reflection for Secure IT Windows Server Installed");
  script_summary(english:"Checks for Attachmate Reflection for Secure IT Windows");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has a SSH server installed on it.");
  script_set_attribute(attribute:"description", value:
"Attachmate Reflection for Secure IT Windows server, a SSH server, is
installed on the remote host.");

  script_set_attribute(attribute:"see_also", value:"http://www.attachmate.com/Products/mft/Security/rist-winserver/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:attachmate:reflection_for_secure_it");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

#if (!get_port_state(port)) exit(0, 'Port '+port+' is not open.');
#soc = open_sock_tcp(port);
#if (!soc) exit(1, 'Failed to open a socket on port '+port+'.');

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

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
exetocheck = NULL;
# Check for versions before 7.x
key = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\fsshconf.exe';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:'Path');
  if (!isnull(item))
  {
    path = item[1];
    exetocheck = 'fssh2console.exe';
  }
  RegCloseKey(handle:key_h);
}

if (isnull(path))
{
  key = 'SOFTWARE\\Classes\\.wst\\shell\\Manage\\command';
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h);
    if (!isnull(item))
    {
      path = item[1];
      path = str_replace(string:path, find:'"', replace:'');
      path = path - strstr(path, '\\rsshd.exe');
      exetocheck = 'sshconsole.exe';
    }
    RegCloseKey(handle:key_h);
  }
}

# We only have a couple versions, so just in case lets check a second
# location for the install path
if (isnull(path))
{
  key = 'SYSTEM\\CurrentControlSet\\Services\\Attachmate Reflection for Secure IT Server';
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:'ImagePath');
    if (!isnull(item))
    {
      path = item[1];
      path = str_replace(string:path, find:'"', replace:'');
      path = path - strstr(path, '\\rsshd.exe');
      exetocheck = 'sshconsole.exe';
    }
    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, 'Attachmate Reflection for Secure IT Windows Server was not detected on the remote host.');
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
exe   = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\' + exetocheck, string:path);
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
  exit(1, 'Couldn\'t open \''+path+'\\' + exetocheck + '\'.');
}

ver = GetFileVersion(handle:fh);

CloseFile(handle:fh);
NetUseDel();

if (isnull(ver))
{
  exit(1, 'Couldn\'t get the version number from \''+path+'\\' + exetocheck + '\'.');
}

version = join(ver, sep:'.');
# Build the version number, and determine the build number
# Assume that anything greater than 9 is not a service pack
if (ver[2] > 9)
{
  verui = ver[0] + '.' + ver[1] + '.0 Build ' + ver[2];
}
else
{
  verui = ver[0] + '.' + ver[1] + '.' + ver[2] + ' Build ' + ver[3];
}

set_kb_item(name:'SMB/Attachmate_Reflection_For_Secure_IT/path', value:path);
set_kb_item(name:'SMB/Attachmate_Reflection_For_Secure_IT/version', value:version);
set_kb_item(name:'SMB/Attachmate_Reflection_For_Secure_IT/verui', value:verui);

register_install(
  app_name:"Attachmate Reflection for Secure IT Windows Server",
  path:path,
  version:version,
  display_version:verui,
  cpe:"cpe:/a:attachmate:reflection_for_secure_it");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + verui + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
