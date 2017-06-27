#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(50574);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:47 $");

  script_name(english:"SmartFTP Detection");
  script_summary(english:"Checks for SmartFTP");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host contains a FTP client.");
  script_set_attribute(attribute:"description", value:"SmartFTP, an FTP client for Windows, is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.smartftp.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

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


# Detect where the software is installed.
#
# nb: don't exit if a key isn't found -- we'll check another location later.
installstring = NULL;

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!isnull(list))
{
  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && 'SmartFTP' >< prod && 'Setup Files' >!< prod)
    {
      installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
      installstring = str_replace(find:"/", replace:"\\", string:installstring);
    }
  }
}


# Connect to the appropriate share
name      = kb_smb_name();
port      = kb_smb_transport();

login     = kb_smb_login();
pass      = kb_smb_password();
domain    = kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Determine where it's installed.
version = NULL;
path = NULL;

# First try to read the install location from the uninstall registry
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Couldn't connect to the remote registry.");
}

if (!isnull(installstring))
{
  key_h = RegOpenKey(handle:hklm, key:installstring, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"InstallLocation");
    if (!isnull(item)) path = item[1];

    RegCloseKey(handle:key_h);
  }
}
if (isnull(path))
{
  # This must be an older version of SmartFTP
  key = "SOFTWARE\SmartFTP";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"Install Directory");
    if (!isnull(item))
    {
      path = item[1];
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(1, "The SmartFTP client install location could not be found in the registry.");
}
NetUseDel(close:FALSE);


# Determine the version from the executable
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\SmartFTP.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to '"+share+"' share.");
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
  exit(0, "Failed to open '"+(share-'$')+":"+exe+"'.");
}

version = GetProductVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();


if (!isnull(version))
{
  kb_base = "SMB/SmartFTP";
  set_kb_item(name:kb_base+"/Path", value:path);
  set_kb_item(name:kb_base+"/Version", value:version);

  register_install(
    app_name:"SmartFTP",
    path:path,
    version:version);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path    : ' + path +
      '\n  Version : ' + version + '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else exit(1, "Couldn't get the product version of '"+(share-'$')+":"+exe+"'.");
