#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51388);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_name(english:"Kerio Control Detection");
  script_summary(english:"Check for Kerio Control / WinRoute");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has a software firewall installed.");

  script_set_attribute(attribute:"description", value:
"Kerio Control (formerly known as Kerio WinRoute) is installed on the
remote Windows host. It acts as a software-based firewall.");

  script_set_attribute(attribute:"see_also", value:"http://www.kerio.com/control");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

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

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
name    = kb_smb_name();
port    = kb_smb_transport();

login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();


if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to the remote registry
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to the remote registry.");
}

# Find where it's installed.
ver = NULL;
path = NULL;

key = "SOFTWARE\Kerio\WinRoute";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "Kerio Control is not installed.");
}

# Grab the file version of file winroute.exe
share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
exe   = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\winroute.exe", string:path);
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

if (isnull(fh))
{
  NetUseDel();
  exit(1, "Failed to open '"+path+"\winroute.exe'.");
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

# Check the version number.
if (!isnull(ver))
{
  version = ver[0] + '.' + ver[1] + '.' + ver[2];
  build = ver[3];
  set_kb_item(name:"SMB/Kerio_Control/Version", value:version);
  set_kb_item(name:"SMB/Kerio_Control/Build", value:build);
  set_kb_item(name:"SMB/Kerio_Control/Path", value:path);

  register_install(
    app_name:"Kerio Control",
    path:path,
    version:version,
    extra:make_array("Build", build));

  if (report_verbosity > 0)
  {
    report =
      '\n  Path    : ' + path +
      '\n  Version : ' + version + ' Build ' + build + '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else exit(1, "Can't get the file version of '"+path+"\winroute.exe'.");
