#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42399);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/12 17:12:47 $");

  script_name(english:"Microsoft Silverlight Detection");
  script_summary(english:"Checks for Microsoft Silverlight");

  script_set_attribute(attribute:'synopsis', value:"The remote host has Microsoft Silverlight installed.");
  script_set_attribute(attribute:'description', value:
"A version of Microsoft's Silverlight is installed on this host.

Microsoft Silverlight is a web application framework that provides
functionalities similar to those in Adobe Flash, integrating
multimedia, graphics, animations and interactivity into a single
runtime environment.");
  script_set_attribute(attribute:'see_also', value:"http://silverlight.net/");
  script_set_attribute(attribute:'solution', value:"n/a");
  script_set_attribute(attribute:'risk_factor', value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

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

# Connect to the appropriate share.
get_kb_item_or_exit("SMB/Registry/Enumerated");

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
  exit(1, "Can't connect to the remote registry.");
}

# Find where it's installed.
clsid = NULL;
dll = NULL;

key = "SOFTWARE\Classes\AgControl.AgControl";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"CLSID");
  if (!isnull(value)) clsid = value[1];

  RegCloseKey(handle:key_h);
}
if (isnull(clsid))
{
  key = "SOFTWARE\Classes\MIME\Database\Content Type\application/x-silverlight";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"CLSID");
    if (!isnull(value)) clsid = value[1];

    RegCloseKey(handle:key_h);
  }
}
if (!isnull(clsid))
{
  key = "SOFTWARE\Classes\CLSID\" + clsid + "\InprocServer32";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) dll = value[1];

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);

if (isnull(dll))
{
  NetUseDel();
  exit(0, "No evidence of Microsoft Silverlight was found in the Windows registry.");
}
NetUseDel(close:FALSE);

# Determine its version from the executable itself.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:dll);
dll2 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:dll);
path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+$', replace:"\1", string:dll, icase:TRUE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to '"+share+"' share.");
}

fh = CreateFile(
  file:dll2,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!fh)
{
  NetUseDel();
  exit(0, "The Silverlight control is not installed, although traces of it exist in the registry.");
}
set_kb_item(name:"SMB/Silverlight/Installed", value:TRUE);
set_kb_item(name:"SMB/Silverlight/Path", value:path);

report = '\n  Path    : ' + path;

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (!isnull(ver))
{
  version = join(sep:".", ver);
  set_kb_item(name:"SMB/Silverlight/Version", value:version);
  report += '\n  Version : ' + version;
}
else version = UNKNOWN_VER;

register_install(
  app_name:"Microsoft Silverlight",
  path:path,
  version:version,
  cpe:"cpe:/a:microsoft:silverlight");

if (report_verbosity > 0)
{
  report += '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
