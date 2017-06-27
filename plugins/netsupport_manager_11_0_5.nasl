#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50547);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/06/23 19:16:51 $");

  script_cve_id("CVE-2010-4184");
  script_bugtraq_id(44629);
  script_osvdb_id(69014);
  script_xref(name:"CERT", value:"465239");
  script_xref(name:"Secunia", value:"42104");

  script_name(english:"NetSupport Manager < 11.00.0005");
  script_summary(english:"Checks version of PCICL32.DLL");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of NetSupport Manager is prior to 11.00.0005. It
is, therefore, affected by an information disclosure vulnerability due
to bundled vulnerable versions of NetSupport Manager clients, and
controls that reveal sensitive information such as IP and MAC
addresses in cleartext HTTP headers while communicating with
NetSupport Manager Gateway. By monitoring traffic between NetSuppor
Manager clients and NetSupport Manager Gateway, an attacker can gain
sensitive information about the client machine.");
 # http://www.netsupportsoftware.com/support/kb/asp/kbprovider.asp?gettd=634&lang=EN&xsl=http%3A//www.netsupportsoftware.com/support/kb/TechDoc.xsl
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92cb9630");
 script_set_attribute(attribute:"solution", value:"Upgrade to NetSupport Manager 11.00.0005 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netsupportsoftware:netsupport_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0, "The 'SMB/Registry/Enumerated' KB item is not set to TRUE.");

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

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

# Find where it's installed.
path = NULL;

key = "SOFTWARE\NetSupport Manager";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "NetSupport Manager is not installed.");
}
NetUseDel(close:FALSE);

# Grab the file version of NetSupport Manager Client DLL
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\PCICL32.DLL", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();
if (isnull(ver)) exit(1, "Couldn't get file version of '"+(share-'$')+":"+dll+"'.");

# Check the version number.
version = join(ver, sep:".");
if (ver_compare(ver:version, fix:'11.0.5',strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 11.00.0005 (11.0.5)\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0,"NetSupport Manager "+ version + " is installed and hence not affected.");
