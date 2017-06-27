#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2012/02/08. Deprecated by smb_nt_ms12-006.nasl.

include('compat.inc');

if (description)
{
  script_id(56333);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/05/13 20:41:06 $");

  script_cve_id("CVE-2011-3389");
  script_bugtraq_id(49778);
  script_osvdb_id(74829);

  script_name(english:"Deprecated");
  script_summary(english:"Checks if RC4 has been prioritized.");

  script_set_attribute(attribute:"synopsis", value:"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated and is no longer functional.  It
was originally written to check Microsoft's workaround for
CVE-2011-3389, but was replaced by plugin 57474 which checks for
the patch that fixes this CVE.");

  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2588513");
  script_set_attribute(attribute:"solution", value:"n/a");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

exit(0, "This plugin has been deprecated. Use smb_nt_ms12-006.nasl (plugin ID 57474) instead");

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');
winver = get_kb_item_or_exit('SMB/WindowsVersion');

if (winver != '6.0') exit(1, 'The workaround only applies to Windows Vista and 2008.');

name    = kb_smb_name();
port    = kb_smb_transport();
if (!get_port_state(port)) exit(1, 'Port '+port+' is not open.');
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(1, 'Can\'t open socket on port '+port+'.');
session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (rc != 1)
{
  NetUseDel();
  exit(1, 'Can\'t connect to IPC$ share.');
}

# Connect to the remote registry
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{

  NetUseDel();
  exit(1, 'Can\'t connect to remote registry.');
}

vuln = FALSE;
suites = make_list();
key = 'SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:'Functions');
  if (isnull(item)) vuln = TRUE;
  else suites = split(item[1], sep:',', keep:FALSE);
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel();

if ((max_index(suites) < 1) && !vuln) exit(1, 'Couldn\'t get the SSL Cipher Suite Order from the remote host.');

if (
  !vuln &&
  suites[0] != 'TLS_RSA_WITH_RC4_128_SHA' &&
  suites[0] != 'TLS_RSA_WITH_RC4_128_MD5' &&
  suites[0] != 'SSL_CK_RC4_128_WITH_MD5'
) vuln = TRUE;
    

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = '\n  The \'RC4\' algorithm hasn\'t been prioritized on the remote host.\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, 'The host is not affected.');
