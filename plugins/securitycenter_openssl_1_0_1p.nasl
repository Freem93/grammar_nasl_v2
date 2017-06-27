#TRUSTED 095f2cbf735b75f2e2c1cfd5a507612405917513e4e4567e7175ffef4be1942a44b22a474ea754ce0a28cc4b524f50ab6e91fb7c8e07a7394f037b8492d9ef65c0f83ffe0190dacc5685fc9d5ead233abab641b0fa54010bff14512009f2d52bc4bc38852901c32288fb2d57fcffd4d53d5881bff994f2178e1c0c2435be8b7f9149b93371409432f1e1a9da82b0fc26d000d246e10f0e4d002df3e120c75fbb395a419213852dbe800df16f48ca5293c6126a8e3886e246c4281eaa04b9fda07950f78d97dfeb9ce860928c158e0fb43f5acf977156ec13cdff6f1cab1ce7c1703a34e9eea14600e4052bbfeb520eb9b5c15010aceba51e2ad1d0b748cd0530b830cbc4d582ac3ed96fb1eaa0ea68015091a96061cbfb2aed50a0c21f340cf88e1b4021f858d82e01f941e2066eb6ac0bc5915e8505671fa6fcc64414189938150026a77e6eb0efe0956742d43e0ae507ca2dce530dcce0aa3804d8e5a6922c015cb3bd8e62f7990fb34e339356b2d3bfe86d909942883da1545a8eef0f82acc3aff1493dea9815ecbfb81ac040d862efddd5833f95f3054f8590de875bcd20e7f15c8919f2dd20dd7b106dc161a46002c209dbba0f0dfc687432f1db58a5a78b935c44ed5e53b2cfe01f01ed2e2f780e1a84e6d1345158642eea9b130bd533e0fd46a84bad6a73f7feac3a5ca9e6c2d4343575da827f1e2dd74be29d6b97c6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85565);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/03");

  script_cve_id("CVE-2015-1793");
  script_bugtraq_id(75652);
  script_osvdb_id(124300);

  script_name(english:"Tenable SecurityCenter Alternative Certificate Validation Bypass Vulnerability (TNS-2015-08)");
  script_summary(english:"Checks the version of OpenSSL in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is affected by a certificate validation bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The SecurityCenter application installed on the remote host is
affected by a certificate validation bypass vulnerability in the
bundled OpenSSL library. The library is version 1.0.1n or later and
prior to 1.0.1p. It is, therefore, affected by a flaw in the
X509_verify_cert() function that is triggered when locating alternate
certificate chains in cases where the first attempt to build such a
chain fails. A remote attacker can exploit this to cause certain
certificate checks to be bypassed, resulting in an invalid certificate
being considered valid.");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/tns-2015-08");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150709.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_keys("Host/SecurityCenter/Version", "Host/local_checks_enabled");

  exit(0);
}

include("openssl_version.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
sc_ver = get_kb_item_or_exit("Host/SecurityCenter/Version");
if (! ereg(pattern:"^(4\.[6-8]\.|5\.0\.[0-1])", string:sc_ver)) audit(AUDIT_INST_VER_NOT_VULN, "SecurityCenter", sc_ver);

# Establish running of local commands
if ( islocalhost() )
{
  if ( ! defined_func("pread") ) audit(AUDIT_NOT_DETECT, "pread");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (! sock_g) audit(AUDIT_HOST_NOT, "able to connect via the provided SSH credentials.");
  info_t = INFO_SSH;
}

fixes = make_list("1.0.1p", "1.0.2d");
cutoffs = make_list("1.0.1n", "1.0.2b");
pattern = "OpenSSL (\d+(?:\.\d+)*(-beta\d+|[a-z]*))";

# Check version
line = info_send_cmd(cmd:"/opt/sc4/support/bin/openssl version");
if (!line) line = info_send_cmd(cmd:"/opt/sc/support/bin/openssl version");

if (!line) audit(AUDIT_UNKNOWN_APP_VER, "OpenSSL (within SecurityCenter)");
match = eregmatch(pattern:pattern, string:line);
if (isnull(match)) audit(AUDIT_UNKNOWN_APP_VER, line);
version = match[1];

fix = NULL;

for ( i=0; i<2; i++)
{
  if (
    openssl_ver_cmp(ver:version, fix:fixes[i], same_branch:TRUE, is_min_check:FALSE) < 0 &&
    openssl_ver_cmp(ver:version, fix:cutoffs[i], same_branch:TRUE, is_min_check:FALSE) >= 0
  )
  {
    fix = fixes[i];
    break;
  }
}

if (!isnull(fix))
{
  report = '\n' +
    '\n  SecurityCenter version         : ' + sc_ver +
    '\n  SecurityCenter OpenSSL version : ' + version +
    '\n  Fixed OpenSSL version          : ' + fix +
    '\n';
  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "OpenSSL (within SecurityCenter)", version);
