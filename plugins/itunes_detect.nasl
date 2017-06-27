#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25996);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/28 22:08:11 $");

  script_name(english:"Apple iTunes Version Detection (credentialed check)");
  script_summary(english:"Checks the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"Apple iTunes is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Apple iTunes, a popular media player, is installed on the remote
Windows host.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

# Get some info about the install.
exe = NULL;

key = "SOFTWARE\Classes\Applications\iTunes.exe\shell\open\command";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item)) exe = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

# If it is...
if (exe)
{
  # Determine its version from the executable itself.
  exe = ereg_replace(pattern:'^"([^"]+)".*$', replace:"\1", string:exe);
  path = ereg_replace(pattern:"^(.+)\\[^\\]+\.exe$", replace:"\1", string:exe);

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:exe);
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:exe);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to "+share+" share.");
  }

  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  ver = NULL;
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  if (!isnull(ver))
  {
    version = join(sep:".", ver);
    set_kb_item(name:"SMB/iTunes/Version", value:version);

    set_kb_item(name:"SMB/iTunes/Path", value:path);

    register_install(
      app_name:"iTunes Version",
      path:path,
      version:version,
      cpe:"cpe:/a:apple:itunes");

    if (report_verbosity > 0)
    {
      report =
        '\n  Path    : ' + path +
        '\n  Version : ' + version + '\n';
      security_note(port:port, extra:report);
    }
    else security_note(port);
  }
}

# Clean up.
NetUseDel();
