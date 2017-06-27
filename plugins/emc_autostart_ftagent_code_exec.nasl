#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55995);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/02/07 18:43:41 $");

  script_cve_id("CVE-2011-2735");
  script_bugtraq_id(49238);
  script_osvdb_id(74597, 97746, 97747);

  script_name(english:"EMC AutoStart ftAgent Multiple Remote Code Execution Vulnerabilities");
  script_summary(english:"Checks version of ftAgent.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of EMC AutoStart on the remote host reportedly contains
multiple remote code execution vulnerabilities :

  - When creating error messages to be written to logs, a
    user controlled string from the packet is used as an
    argument to a function containing a format string. The
    result of that function is written to a statically-sized
    buffer on the stack, which can result in a buffer
    overflow.

  - ftAgent.exe, when processing messages with opcode 0x11,
    performs arithmetic on an unvalidated user-supplied
    value used to determine the size of a new heap buffer.
    This allows a potential integer wrap to cause a heap-
    based buffer overflow.

  - ftAgent.exe, when processing messages with opcode 0x140,
    performs arithmetic on an unvalidated user-supplied
    value used to determine the size of a new heap buffer.
    This allows a potential integer wrap to cause a heap-
    based buffer overflow.

Failed attacks may result in a denial of service.");

  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/519371");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-273/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-274/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-275/");

  script_set_attribute(attribute:"solution", value:"Upgrade to version 5.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-185");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:autostart");
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

# Connect to the appropriate share.
name    =  kb_smb_name();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();


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

# Get the domain from the registry.
domain = NULL;
key = "SOFTWARE\FullTime Software\FullTime Cluster";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"FT_DOMAINNAME");
  if (!isnull(item))
    domain = item[1];
  RegCloseKey(handle:key_h);
}

if (isnull(domain))
{
  NetUseDel();
  exit(0, "EMC AutoStart does not appear to be installed.");
}

# Get the installation path from the registry.
base = NULL;
key_h = RegOpenKey(handle:hklm, key:key + "\" + domain, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"FT_DIR");
  if (!isnull(item))
    base = ereg_replace(string:item[1], pattern:"^(.+)\\$", replace:"\1");
  RegCloseKey(handle:key_h);
}

if (isnull(base))
{
  NetUseDel();
  exit(0, "Could not get path to EMC AutoStart's domain.");
}

# Clean up.
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

# Split the software's location into components.
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
path = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");
file = "\bin\ftAgent.exe";

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Failed to connect to " + share + " share.");
}

# Get the version number from the main executable.
version = NULL;
fh = CreateFile(
  file:path + file,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  exit(0, "EMC AutoStart is no longer installed.");
}
version = GetFileVersion(handle:fh);
CloseFile(handle:fh);

# Clean up.
NetUseDel();

# Ensure that we got a version number.
if (isnull(version))
  exit(1, "Failed to get version of " + base + file + ".");

# Check if the version is vulnerable.
fixed = "5.4.1.73";
version = join(version, sep:".");
if (version !~ "^5\.[34]" || ver_compare(ver:version, fix:fixed, strict:TRUE) >= 0)
  exit(0, "EMC AutoStart version " + version + " is not vulnerable.");

# Report our findings.
if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + base +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
