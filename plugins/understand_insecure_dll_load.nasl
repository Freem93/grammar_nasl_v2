#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57891);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_cve_id("CVE-2012-4755");
  script_bugtraq_id(51910);
  script_osvdb_id(78986);

  script_name(english:"Scientific Toolworks Understand 'wintab32.dll' DLL Loading Arbitrary Code Execution");
  script_summary(english:"Checks for the version of understand.exe.");

  script_set_attribute(attribute:"synopsis", value:
"A program installed on the remote Windows host is affected by an
insecure DLL loading vulnerability.");

  script_set_attribute(attribute:"description", value:
"The version of Scientific Toolworks Understand installed on the remote
Windows host is earlier than 2.6 Build 600. As such, it insecurely
looks in its current working directory when resolving DLL
dependencies, such as for 'wintab32.dll'.

Attackers may exploit this issue by placing a specially crafted DLL
file and another file associated with the application in a location
controlled by the attacker. When the associated file is launched, the
attacker's arbitrary code can be executed.");

  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.6 Build 600 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"see_also", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5071.php");
  script_set_attribute(attribute:"see_also", value:"http://www.scitools.com/support/buildLogs.php");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/10");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:scitools:understand");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

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

function get_version(fh)
{
  local_var blob, build, chunk, length, line, lines, matches, ofs;
  local_var overlap, pat_build, pat_version, version;

  length = GetFileSize(handle:fh);
  if (length == 0)
    return NULL;

  # Choose starting offset.
  if (length < 100000) ofs = 0;
  else ofs = int((length / 10) * 5);
  ofs = 0;

  overlap = 50;
  chunk = 10240;

  build = NULL;
  version = NULL;

  while (ofs <= length && (isnull(version) || isnull(build)))
  {
    blob = ReadFile(handle:fh, length:chunk, offset:ofs);
    if (strlen(blob) == 0) break;
    blob = str_replace(string:blob, find:raw_string(0), replace:" ");

    # These patterns have been verified for version 2.6 Build 598 and
    # 600. Note that the version and build numbers appear in entirely
    # different parts of the binary.
    pat_build = "\(Build ([0-9]+)\) ";
    pat_version = "About %1 ([0-9.]+) %2";

    lines = egrep(string:blob, pattern:pat_version);
    foreach line (split(lines))
    {
      matches = eregmatch(string:line, pattern:pat_version);
      if (!isnull(matches))
      {
        version = matches[1];
        break;
      }
    }

    lines = egrep(string:blob, pattern:pat_build);
    foreach line (split(lines))
    {
      matches = eregmatch(string:line, pattern:pat_build);
      if (!isnull(matches))
      {
        build = matches[1];
        break;
      }
    }

    ofs += chunk - overlap;
  }

  if (isnull(version) || isnull(build))
    return NULL;

  return make_list(version, build);
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

# Get the location the software was installed at.
base = NULL;

key = "SOFTWARE\Scitools";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^Understand")
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        # The path id in the '(Default)' key, which can be accessed by
        # using an empty string.
        item = RegQueryValue(handle:key2_h, item:"");
        if (!isnull(item))
        {
          base = ereg_replace(string:item[1], pattern:"^(.+)\\$", replace:"\1");
          break;
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (isnull(base))
{
  NetUseDel();
  exit(0, "Scientific Toolworks Understand is not installed on the remote host.");
}

# Split the software's location into components.
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
dir = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");
path = "\bin\pc-win32\understand.exe";

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Failed to connect to " + share + " share.");
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
  exit(0, "Scientific Toolworks Understand is no longer installed on the remote host.");
}

# Find the version string in the executable.
res = get_version(fh:fh);
CloseFile(handle:fh);

# Clean up.
NetUseDel();

if (isnull(res))
  exit(1, "Failed to extract the version number from " + base + path + ".");

# Check if the installation is vulnerable.
if (ver_compare(ver:join(res, sep:"."), fix:"2.6.600", strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + base + path +
      '\n  Installed version : ' + res[0] + ' Build ' + res[1] +
      '\n  Fixed version     : 2.6 Build 600' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The Scientific Toolworks Understand install at " + base + " is not affected.");
