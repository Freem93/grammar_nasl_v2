#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55594);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_cve_id("CVE-2011-1222", "CVE-2011-1223");
  script_bugtraq_id(48519);
  script_osvdb_id(73552, 73553);
  script_xref(name:"Secunia", value:"45098");

  script_name(english:"IBM Tivoli Storage Manager Client Multiple Buffer Overflows (swg21457604)");
  script_summary(english:"Does a version check on the TSM client's web server");

  script_set_attribute(attribute:"synopsis", value:"The remote backup client is susceptible to multiple local attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an IBM Tivoli Storage Manager (TSM) client.
The version running on the remote host has one or more of the
following vulnerabilities :

  - A stack-based buffer overflow exists in the Journal
    Based Backup function because it fails to properly
    sanitize user-supplied input and could allow a local
    attacker to execute arbitrary code. (CVE-2011-1222)

  - A stack-based buffer overflow exists in the Alternate
    Data Streams function because it fails to properly
    sanitize user-supplied input and could allow a local
    attacker to execute arbitrary code. (CVE-2011-1223)");

  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg1IC77049");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg1IC77052");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21457604");

  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant version of Tivoli Storage Manager client
referenced in the vendor's advisory.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/14");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_client");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager");
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

# Get the location of the TSM Client installation.
base = NULL;

key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\IBM\ADSM\CurrentVersion\BackupClient", mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(item))
    base = ereg_replace(string:item[1], pattern:"^(.+)\\$", replace:"\1");

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(base))
{
  NetUseDel();
  exit(0, "Tivoli Storage Manager Client is not installed on the remote host.");
}

# Split the software's location into components.
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
dir = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");
file = "\dsm.exe";
NetUseDel(close:FALSE);

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Failed to connect to " + share + " share.");
}

# Try and read the main executable.
fh = FindFile(
  file               : dir + file,
  desired_access     : GENERIC_READ,
  file_attributes    : FILE_ATTRIBUTE_NORMAL,
  share_mode         : FILE_SHARE_READ,
  create_disposition : OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  exit(0, "Failed to open '" + base + file + "'.");
}

# Extract version information from the main executable.
iver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(iver))
  exit(1, "Failed to extract the file version from '" + base + file + "'.");
ver = join(iver, sep:".");

# Determine if the version is vulnerable.
fix = NULL;
unsupported = FALSE;

if (iver[0] < 5 || (iver[0] == 5 && iver[1] <= 3))
{
  unsupported = TRUE;
  fix = "5.4.3.4 / 5.5.3 / 6.1.4 / 6.2.2";
}
if (iver[0] == 5)
{
  # 5.4.x < 5.4.3.4
  if (iver[1] == 4)
    fix = "5.4.3.4";

  # 5.5.x < 5.5.3
  else if (iver[1] == 5)
    fix = "5.5.3";
}
else if (iver[0] == 6)
{
  # 6.1.x < 6.1.4
  if (iver[1] == 1)
    fix = "6.1.4";

  # 6.2.x < 6.2.2
  else if (iver[1] == 2)
    fix = "6.2.2";
}

if (isnull(fix) || (!unsupported && ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0))
  exit(0, "Tivoli Storage Manager Client version " + ver + " is installed on the remote host, which is not vulnerable.");

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
