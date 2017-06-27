#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82295);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2015-0204");
  script_bugtraq_id(71936);
  script_osvdb_id(116794);
  script_xref(name:"CERT", value:"243585");

  script_name(english:"BlackBerry Enterprise Server SSL/TLS EXPORT_RSA Ciphers Downgrade MitM (KB36811) (FREAK)");
  script_summary(english:"Checks the version of tcnative-1.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by the
FREAK vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of BlackBerry Enterprise Server on the remote host is
affected by a security feature bypass vulnerability, known as FREAK
(Factoring attack on RSA-EXPORT Keys), due to the support of weak
EXPORT_RSA cipher suites with keys less than or equal to 512 bits.
A man-in-the-middle attacker may be able to downgrade the SSL/TLS
connection to use EXPORT_RSA cipher suites which can be factored in a
short amount of time, allowing the attacker to intercept and decrypt
the traffic.");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"see_also", value:"http://www.blackberry.com/btsc/KB36811");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 10.2 MR5 and later with Interim Security Update
BES 12.1 for March 19, 2016, or to version 12.1 and later with Interim
Security Update BES 10.2.5 for March 19 2016");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:blackberry:enterprise_server");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("blackberry_es_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("charset_func.inc");
include("byte_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

prod    = get_kb_item_or_exit("BlackBerry_ES/Product");
version = get_kb_item_or_exit("BlackBerry_ES/Version");
base    = get_kb_item_or_exit("BlackBerry_ES/Path");

if (
  !(
    (version =~ "^10\.[01]($|[^0-9])")     ||
    (version =~ "^10\.2\.[0-5]($|[^0-9])") ||
    (version =~ "^12\.[01]($|[^0-9])")
  )
)
  audit(AUDIT_NOT_INST, "BES 10.x / 12.x");

# Connect to the appropriate share.
port   =  kb_smb_transport();
login  =  kb_smb_login();
pass   =  kb_smb_password();
domain =  kb_smb_domain();

if (version =~ "^12\.")
  path   = base + "\BWCN\bin";
else
  path   = base + "\RIM.BUDS.BWCN\bin";

# Try to connect to server.
if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

openssl_ver = NULL;
file        = "\tcnative-1.dll";

# Split the software's location into components.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dir   = ereg_replace(string:path, pattern:"^[A-Za-z]:(.*)", replace:"\1");

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:dir + file,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  audit(AUDIT_VER_FAIL, dir + file);
  NetUseDel();
}

fsize = GetFileSize(handle:fh);

# Jump to early occurance of
# OpenSSL version string, e.g.,
# OpenSSL 1.0.1l 15 Jan 2015
if (fsize < 696000) off = 0;
else off = 696000;

# Read file while looking for traces
# of OpenSSL version strings.
while (fsize > 0 && off <= fsize)
{
  data = ReadFile(handle:fh, length:16384, offset:off);

  if (strlen(data) == 0)
    break;
  else
    strings = get_strings(buf:data, null_term:TRUE);

  foreach candidate (strings)
  {
    # Looking for :
    # OpenSSL 1.0.1c 10 May 2012
    # or like :
    # DTLSv1 part of OpenSSL 1.0.1c 10 May 2012
    # TXT_DB part of OpenSSL 1.0.1c 10 May 2012
    openssl_pattern = "^(\w+ \w+ \w+ )?(OpenSSL ([0-9.]+([a-z]+)?))";
    matches = eregmatch(string:candidate, pattern:openssl_pattern);

    if (matches)
    {
      openssl_ver = matches[3];
      break;
    }
  }
  off += 16384;
}
CloseFile(handle:fh);
NetUseDel();

if (
  openssl_ver =~ "^0\."                    ||
  openssl_ver =~ "^1\.0\.0($|[^0-9])"      ||
  openssl_ver =~ "^1\.0\.1[a-k]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Product                : ' + prod +
      '\n  Product version        : ' + version +
      '\n  File name              : ' + path + file +
      '\n  File\'s OpenSSL version : ' + openssl_ver +
      '\n  Fixed OpenSSL version  : 1.0.1l' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, prod, version);
