#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57364);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/03/06 15:11:34 $");

  script_name(english:"PuTTY Detection");
  script_summary(english:"Checks for the presence of PuTTY");

  script_set_attribute(attribute:"synopsis", value:"A Telnet / SSH client is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host has an installation of PuTTY, which is a suite of
tools for remote console access and file transfer.");
  script_set_attribute(attribute:"see_also", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/21");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:simon_tatham:putty");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

function get_version(fh)
{
  local_var blob, chunk, length, line, lines, matches, ofs, overlap;
  local_var pattern;

  length = GetFileSize(handle:fh);
  if (length == 0)
    return NULL;

  # Choose starting offset.
  if (length < 100000) ofs = 0;
  else ofs = int((length / 10) * 5);

  overlap = 30;
  chunk = 10240;
  while (ofs <= length)
  {
    blob = ReadFile(handle:fh, length:chunk, offset:ofs);
    if (strlen(blob) == 0) break;
    blob = str_replace(string:blob, find:raw_string(0), replace:" ");

    # This pattern has been verified for versions 0.53 - 0.58.
    pattern = "PuTTY-Release-([a-zA-Z0-9.]+)";

    lines = egrep(string:blob, pattern:pattern);
    foreach line (split(lines))
    {
      matches = eregmatch(string:line, pattern:pattern);
      if (!isnull(matches))
	return matches[1];
    }

    ofs += chunk - overlap;
  }

  return NULL;
}

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Detect PuTTY's information from its uninstall info.
list = get_kb_list_or_exit("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");

key = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && prod =~ "^PuTTY")
  {
    key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
    key = str_replace(find:"/", replace:"\", string:key);
    break;
  }
}
if (isnull(key)) exit(0, "PuTTY does not appear to be installed on the remote host.");

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

# Connect to IPC share.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Get the details of the PuTTY installation.
base = NULL;
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # Get the path at which PuTTY is installed.
  foreach subkey (make_list("InstallLocation", "Inno Setup: App Path"))
  {
    item = RegQueryValue(handle:key_h, item:subkey);
    if (!isnull(item))
    {
      base = ereg_replace(string:item[1], pattern:"^(.+)\\$", replace:"\1");
      break;
    }
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(base))
{
  NetUseDel();
  exit(1, "Failed to read PuTTY's installation path from the registry.");
}

# Split the software's location into components.
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
dir = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");
file = "\putty.exe";
NetUseDel(close:FALSE);

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

# Try and read the main executable.
fh = CreateFile(
  file               : dir + file,
  desired_access     : GENERIC_READ,
  file_attributes    : FILE_ATTRIBUTE_NORMAL,
  share_mode         : FILE_SHARE_READ,
  create_disposition : OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  exit(0, "PuTTY no longer seems to be installed on the remote system.");
}

# Extract version information from the main executable.
version = GetFileVersion(handle:fh);
if (!isnull(version))
{
  # Format extracted version as a string.
  ver = join(version, sep:".");
  if (ver =~ "^[0.]+$") version = NULL;
}

if (isnull(version))
{
  # Grep the binary for the version string.
  version = get_version(fh:fh);
  if (!isnull(version)) ver = version;
}
CloseFile(handle:fh);

NetUseDel();

if (isnull(version))
  exit(1, "Failed to extract the version number from '" + base + file + "'.");

# At least one version of PuTTY ends with a letter, which ver_compare() can't
# handle.
matches = eregmatch(string:ver, pattern:"^([0-9.]+)");
if (isnull(matches)) exit(1, "Failed to extract numeric portion of version " + ver + ".");
num = matches[1];

register_install(
  app_name:"PuTTY",
  path:base,
  version:ver,
  extra:make_array("VersionNumber", num),
  cpe:"cpe:/a:simon_tatham:putty");

# Report our findings.
report_installs();
