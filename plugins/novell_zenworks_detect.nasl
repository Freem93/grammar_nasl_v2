#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58445);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_name(english:"Novell ZENworks Detection");
  script_summary(english:"Reads version locally from app's 'version.txt'");

  script_set_attribute(attribute:"synopsis", value:
"A suite of computer systems management software is installed on the
remote host.");
  script_set_attribute(attribute:"description", value:
"Novell ZENworks is a suite of software that is used for managing
devices throughout their life cycle.");

  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/products/zenworks/");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:zenworks");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Connect to IPC share.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, 'IPC$');
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Get the location the software was installed at.
base = NULL;
file = NULL;

key = "SOFTWARE\Novell\ZCM";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"AgentInstallPath");
  if (!isnull(item))
    base = ereg_replace(string:item[1], pattern:"^(.+)\\$", replace:"\1");

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (isnull(base))
{
  NetUseDel();
  audit(AUDIT_NOT_INST, "Novell ZENworks");
}

# Split the software's location into components.
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
dir = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");
path = "\version.txt";

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

# Try to open the program's main executable.
fh = CreateFile(
  file:dir + path,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  audit(AUDIT_UNINST, "Novell ZENworks");
}

# The file only contains the version string.
ver = ReadFile(handle:fh, length:1024, offset:0);
CloseFile(handle:fh);
NetUseDel();

if (isnull(ver))
  audit(AUDIT_VER_FAIL, base + path);

# parse out just numerical portion
item = eregmatch(pattern:"^([0-9][0-9.]+[0-9])", string:ver);

version = item[1];

# Save the installation information for later.
key = "SMB/Novell/ZENworks/";
set_kb_item(name:key + "Installed", value:TRUE);
set_kb_item(name:key + "Path", value:base);
set_kb_item(name:key + "Version", value:version);
set_kb_item(name:key + "VersionSrc", value:ver);

filtered_str =
  str_replace(string:ver, find:'\n', replace:' ');
filtered_str =
  str_replace(string:filtered_str, find:'\r', replace:'');

# Report our findings.

register_install(
  app_name:"Novell ZENworks",
  path:base,
  version:filtered_str,
  cpe:"cpe:/a:novell:zenworks");
if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + base +
    '\n  Version : ' + filtered_str +
    '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
