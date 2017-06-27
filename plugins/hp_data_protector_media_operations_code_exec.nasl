#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57862);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/18 20:40:53 $");

  script_cve_id("CVE-2011-4791");
  script_bugtraq_id(47004);
  script_osvdb_id(75356);
  script_xref(name:"IAVB", value:"2012-B-0016");

  script_name(english:"HP Data Protector Media Operations Server 'DBServer.exe' Remote Code Execution");
  script_summary(english:"Checks for the version of DBServer.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of HP Data Protector Media
Operations Server on the remote host allows an attacker to execute
arbitrary code on the affected host with SYSTEM privileges due to a
buffer overflow.

Note that the vendor reports only Windows installs are affected.");
  script_set_attribute(attribute:"solution", value:"Apply the SMO A.06.20.01 patch as described in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-112/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Mar/220");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b3eef63");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/08");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storage_data_protector");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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
file = NULL;

key = "SOFTWARE\Hewlett-Packard\MediaOps";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"ClientPath");
  if (!isnull(item))
    base = ereg_replace(string:item[1], pattern:"^(.+)\\$", replace:"\1");

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (isnull(base))
{
  NetUseDel();
  exit(0, "HP Data Protector Media Operations Server is not installed on the remote host.");
}

# Split the software's location into components.
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
dir = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");
path = "\DBServer\DBServer.exe";

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
  exit(0, "HP Data Protector Media Operations Server is no longer installed on the remote host.");
}

# Find the version string in the executable.
ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);

# Clean up.
NetUseDel();

if (isnull(ver))
  exit(1, "Failed to extract the version number from " + base + path + ".");
version = join(ver, sep:".");

# Check if the installation is vulnerable.
fixed = "12.3.99.664";
if (ver_compare(ver:version, fix:fixed, strict:FALSE) < 0)
{
  if ( report_verbosity > 0 )
  {
    report =
      '\n  Path              : ' + base + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The HP Data Protector Media Operations Server install at " + base + path + " is not affected.");
