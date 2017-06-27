#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55577);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/02/07 18:43:41 $");

  script_cve_id("CVE-2011-1867");
  script_bugtraq_id(48527);
  script_osvdb_id(73597);
  script_xref(name:"Secunia", value:"45129");

  script_name(english:"HP iNode Management Center Remote Code Execution (HPSB3C02687)");
  script_summary(english:"Checks the version of iNode Management Center.");

  script_set_attribute(attribute:"synopsis", value:
"The version of iNode Management Center contains a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has an installation of HP iNode Management
Center that is affected by a remote code execution vulnerability. An
unauthenticated remote attacker can send a specially crafted packet
that could result in a stack-based buffer overflow. A successful
attack will allow running arbitrary code with SYSTEM privileges.");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-232/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Jul/8");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe8b44ed");

  script_set_attribute(attribute:"solution", value:
"Upgrade to iNode Management Center 5.00.0103, which is distributed
with UAM 5.0 SP1 E0101P03.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-729");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/13");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:inode_management_center_pc");
  script_set_attribute(attribute:"plugin_type", value:"local");
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

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Detect iNode Management Center's information from its uninstall info.
key = NULL;

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!isnull(list))
{
  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && prod =~ "^iNode Management Center")
    {
      key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
      key = str_replace(find:"/", replace:"\", string:key);
      break;
    }
  }
}

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

# Try to connect to server.


if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Connect to IPC share.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Failed to connect to IPC share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Failed to connect to the remote registry.");
}

# Get the version and location of the iNode Management Center installation.
base = NULL;
ver = NULL;

if (!isnull(key))
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"InstallLocation");
    if (!isnull(item))
      base = ereg_replace(string:item[1], pattern:"^(.+)\\$", replace:"\1");

    item = RegQueryValue(handle:key_h, item:"DisplayVersion");
    if (!isnull(item))
      ver = item[1];

    RegCloseKey(handle:key_h);
  }
}

# Fall back to another key for the base directory if necessary.
if (isnull(base))
{
  key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\h3c\inodecenter", mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"InstallDir");
    if (!isnull(item))
      base = ereg_replace(string:item[1], pattern:"^(.+)\\$", replace:"\1");
    RegCloseKey(handle:key_h);
  }
}

# Fall back to another key for the version if necessary.
if (isnull(ver))
{
  key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\HP\iNode Management Center", mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    info = RegQueryInfoKey(handle:key_h);
    for (i = 0; i < info[1] && isnull(ver); i++)
    {
      subkey = RegEnumKey(handle:key_h, index:i);
      if (subkey =~ "[0-9.]+") ver = subkey;
    }

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);

if (isnull(base) && isnull(ver))
{
  NetUseDel();
  exit(0, "iNode Management Center is not installed on the remote host.");
}

if (isnull(base))
{
  NetUseDel();
  exit(1, "Failed to read iNode Management Center's installation path from the registry.");
}

if (isnull(ver))
{
  NetUseDel();
  exit(1, "Failed to read iNode Management Center's version from the registry.");
}

# Split the software's location into components.
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
dir = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");
file = "\iNodeMngChecker.exe";
NetUseDel(close:FALSE);

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Failed to connect to " + share + " share.");
}

# Confirm that the file we're interested in is actually in place.
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
  exit(0, "iNode Management Center is no longer installed on the remote host.");
}
CloseFile(handle:fh);

NetUseDel();

# Check if the installed version is vulnerable.
fix = "5.00.0103";
if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  exit(0, "iNode Management Center " + ver + " is installed and not affected.");

# Report our findings.
if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + base +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
