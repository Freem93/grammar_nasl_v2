#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54644);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_cve_id("CVE-2011-2386");
  script_bugtraq_id(47948);
  script_osvdb_id(72464);
  script_xref(name:"EDB-ID", value:"17317");
  script_xref(name:"Secunia", value:"44636");

  script_name(english:"VisiWave Site Survey Report VWR File Handling Overflow");
  script_summary(english:"Checks version of VisiWave");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a file
handling overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VisiWave Site Survey on the remote host is earlier than
2.1.9 and thus reportedly contains a file handling overflow. If an
attacker provides a malicious VWR file and convinces a user to open it
with VisiWave, VisiWave may execute malicious code in the context of
the user.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b223c9f4");

  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.1.9 or above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'VisiWave VWR File Parsing Vulnerability');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/25");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:visiwave:site_survey");
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

# Get the installation path from the registry.
base = NULL;
key = "SOFTWARE\AZO Technologies, Inc.\VisiWave Site Survey";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(item))
    base = ereg_replace(string:item[1], pattern:"^(.+)\\$", replace:"\1");
  RegCloseKey(handle:key_h);
}

# Clean up.
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

# Check if VisiWave is installed.
if (isnull(base))
{
  NetUseDel();
  exit(0, "VisiWave does not appear to be installed.");
}

# Split the software's location into components.
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
path = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");
file = "\VisiWave.exe";

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
if (!isnull(fh))
{
  version = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
else
{
  NetUseDel();
  exit(1, "Failed to open " + base + file + ".");
}

# Clean up.
NetUseDel();

# Ensure that we got a version number.
if (isnull(version))
  exit(1, "Failed to get version of " + base + file + ".");

# Check if the version is vulnerable.
fixed = "2.1.9.162";
version = join(version, sep:".");
if (ver_compare(ver:version, fix:fixed, strict:TRUE) >= 0)
  exit(0, "VisiWave version " + version + " is not vulnerable.");

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
