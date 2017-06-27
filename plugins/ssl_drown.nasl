#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89058);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/07/19 18:40:13 $");

  script_cve_id("CVE-2016-0800");
  script_bugtraq_id(83733);
  script_osvdb_id(135149);
  script_xref(name:"CERT", value:"583776");

  script_name(english:"SSL DROWN Attack Vulnerability (Decrypting RSA with Obsolete and Weakened eNcryption)");
  script_summary(english:"Checks for vulnerable SSLv2 services");

  script_set_attribute(attribute:"synopsis", value:
"The remote host may be affected by a vulnerability that allows a
remote attacker to potentially decrypt captured TLS traffic.");
  script_set_attribute(attribute:"description", value:
"The remote host supports SSLv2 and therefore may be affected by a
vulnerability that allows a cross-protocol Bleichenbacher padding
oracle attack known as DROWN (Decrypting RSA with Obsolete and
Weakened eNcryption). This vulnerability exists due to a flaw in the
Secure Sockets Layer Version 2 (SSLv2) implementation, and it allows
captured TLS traffic to be decrypted. A man-in-the-middle attacker can
exploit this to decrypt the TLS connection by utilizing previously
captured traffic and weak cryptography along with a series of
specially crafted connections to an SSLv2 server that uses the same
private key.");
  script_set_attribute(attribute:"see_also", value:"https://drownattack.com/");
  script_set_attribute(attribute:"see_also", value:"https://drownattack.com/drown-attack-paper.pdf");
  script_set_attribute(attribute:"solution", value:
"Disable SSLv2 and export grade cryptography cipher suites. Ensure that
private keys are not used anywhere with server software that supports
SSLv2 connections.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/03/01");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/01");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl", "ssl_supported_ciphers.nasl");
  script_require_keys("SSL/Supported");
  script_exclude_keys("global_settings/disable_ssl_cipher_neg");
  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

get_kb_item_or_exit("SSL/Supported");

port = get_ssl_ports(fork:TRUE);
if (isnull(port)) audit(AUDIT_HOST_NONE, "SSL-based services");
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

vuln = FALSE;
ssl_versions = get_kb_list_or_exit("SSL/Transport/" + port);
foreach version (ssl_versions)
  if(version == ENCAPS_SSLv2) vuln = TRUE; 

if(!vuln)
  audit(AUDIT_NOT_LISTEN, 'SSLv2 service', port);

# only flag if affected cipher suite is present as well if report paranoia isn't turned up
if (report_paranoia < 2) vuln = FALSE;

# cipher suites are from SSL DROWN scan tool
vuln_cipher_suites_regex =
  "(" +
    # RC4_128_WITH_MD5
    "_RC4_128_WITH_MD5" +
      "|" +

    # RC4_128_EXPORT40_WITH_MD5
    "_RC4_128_EXPORT40_WITH_MD5" +
      "|" +

    # RC2_128_CBC_EXPORT40_WITH_MD5
    "_RC2_128_CBC_EXPORT40_WITH_MD5" +
      "|" +

    # DES_64_CBC_WITH_MD5
    "_DES_64_CBC_WITH_MD5" +
   ")";

supported_ciphers = get_kb_list_or_exit("SSL/Ciphers/" + port);
supported_ciphers = make_list(supported_ciphers);

if (!max_index(supported_ciphers)) exit(1, "No ciphers were found for port " + port + ".");

c_report = cipher_report(supported_ciphers, name:vuln_cipher_suites_regex);

if (!isnull(c_report)) vuln = TRUE;

# this can only get called on report_paranoia > 1 scans
if(!vuln) exit(0, "The SSLv2 service on port " + port + " does not support a vulnerable cipher suite.");

if(isnull(c_report))
  report = '\nThe remote host supports SSLv2 and may be affected by SSL DROWN.';
else report = '\nThe remote host is affected by SSL DROWN and supports the following'+
              '\nvulnerable cipher suites :\n' + c_report;

security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
