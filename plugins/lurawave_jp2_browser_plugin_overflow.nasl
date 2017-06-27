#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57940);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_cve_id("CVE-2012-0978");
  script_bugtraq_id(51732);
  script_osvdb_id(78662);
  script_xref(name:"Secunia", value:"47831");

  script_name(english:"LuraWave JP2 Browser Plug-In < 2.1.1.11 npjp2.dll Remote Buffer Overflow");
  script_summary(english:"Checks the version of the DLL");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plug-in that is affected by a
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the LuraWave JP2 Browser Plug-In installed on the
remote Windows host is earlier than 2.1.1.11 and thus reportedly
contains a stack-based buffer overflow vulnerability.

If an attacker can trick a user on the affected host into viewing a
specially crafted HTML document, he can leverage this issue to execute
arbitrary code on the affected system subject to the user's
privileges.");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.1.1.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:luratech:lurawave_jp2_browser_plug-in");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "opera_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_activex_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Detect LuraWave's presence by searching the uninstall information.
# Unfortunately, the browser plugin doesn't store any paths.
list = get_kb_list_or_exit("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");

installed = FALSE;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && prod == "LuraTech Browser Plug-Ins")
  {
    installed = TRUE;
    break;
  }
}
if (!installed) exit(0, "The LuraWave JP2 Browser Plug-In does not appear to be installed on the remote host.");

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

bases = make_list();

# Find where Mozilla keeps its extensions.
key = "SOFTWARE\Mozilla";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i = 0; i < info[1]; i++)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^Mozilla Firefox ")
    {
      key2 = key + "\" + subkey + "\Extensions";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:"Plugins");
        if (!isnull(item))
          bases = make_list(bases, item[1]);
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

# Find where Opera keeps its extensions.
base = get_kb_item("SMB/Opera/Path");
if (!isnull(base))
  bases = make_list(bases, base + "\Program\Plugins");

# Examine all the plugin directories and check the version number of the
# LuraWave JP2 plugin if it exists.
dlls = make_array();
path = "\npjp2.dll";
prev = NULL;

foreach base (bases)
{
  # Split the software's location into components.
  share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
  dir = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");

  # Connect to the share software is installed on.
  if (share != prev)
  {
    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      NetUseDel();
      exit(1, "Failed to connect to " + share + " share.");
    }
  }

  # Try to open the DLL.
  fh = CreateFile(
    file:dir + path,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh)) continue;

  # Find the version string in the DLL.
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
  if (isnull(ver)) continue;

  # Store the version if it's vulnerable.
  ver = join(ver, sep:".");
  if (ver_compare(ver:ver, fix:"2.1.1.11", strict:FALSE) < 0)
    dlls[base + path] = ver;
}
NetUseDel();

num = max_index(keys(dlls));
if (num == 0)
  exit(0, "No affected instances of the LuraWave JP2 Browser Plug-In are installed on the remote host.");

if (report_verbosity > 0)
{
  # Handle singular and plural findings.
  if (num > 1) s = "s of the LuraWave JP2 Browser Plug-In are";
  else s = " of the LuraWave JP2 Browser Plug-In is";

  report =
    '\nThe following vulnerable instance' + s + ' installed :' +
    '\n';

  foreach dll (keys(dlls))
  {
    report +=
      '\n  Path              : ' + dll +
      '\n  Installed version : ' + dlls[dll] +
      '\n  Fixed version     : 2.1.1.11' +
      '\n';
  }

  security_hole(port:port, extra:report);
}
else security_hole(port);
