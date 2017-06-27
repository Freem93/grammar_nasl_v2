#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3208 ) exit(0);

include("compat.inc");

if (description)
{
  script_id(35291);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/05/01 17:20:08 $");

  script_cve_id("CVE-2004-2761");
  script_bugtraq_id(11849, 33065);
  script_osvdb_id(45106, 45108, 45127);
  script_xref(name:"CERT", value:"836068");

  script_name(english:"SSL Certificate Signed Using Weak Hashing Algorithm");
  script_summary(english:"Checks signature algorithm used to sign SSL certificates in chain.");

  script_set_attribute(attribute:"synopsis", value:
"An SSL certificate in the certificate chain has been signed using a
weak hash algorithm.");
  script_set_attribute(attribute:"description", value:
"The remote service uses an SSL certificate chain that has been signed
using a cryptographically weak hashing algorithm (e.g. MD2, MD4, MD5,
or SHA1). These signature algorithms are known to be vulnerable to
collision attacks. An attacker can exploit this to generate another
certificate with the same digital signature, allowing an attacker to
masquerade as the affected service.

Note that this plugin reports all SSL certificate chains signed with
SHA-1 that expire after January 1, 2017 as vulnerable. This is in
accordance with Google's gradual sunsetting of the SHA-1 cryptographic
hash algorithm.

Note that certificates in the chain that are contained in the Nessus
CA database (known_CA.inc) have been ignored.");
  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc3279");
  # https://web.archive.org/web/20170429062248/http://www.phreedom.org/research/rogue-ca/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e120eea1");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/961509");
  script_set_attribute(attribute:"solution", value:
"Contact the Certificate Authority to have the certificate reissued.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ietf:md5");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ietf:x.509_certificate");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("ssl_certificate_chain.nasl");
  script_require_keys("SSL/Chain/WeakHash");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

# Get the port that has a weak hash algorithm from the KB.
key = "SSL/Chain/WeakHash";
port = get_kb_item_or_exit(key);
key += "/" + port;

# If the user doesn't want the details, let's stop right here.
if (report_verbosity == 0)
{
  security_warning(port);
  exit(0);
}

# Get the list of certificates with weak hash algorithms.
certs = get_kb_list_or_exit(key);

# Add the certificates to the report.
attrs = make_list();
foreach attr (certs)
{
  attrs = make_list(attrs, attr);
}

# Report our findings.
report =
  '\nThe following certificates were part of the certificate chain sent by' +
  '\nthe remote host, but contain hashes that are considered to be weak.' +
  '\n' +
  '\n' + cert_report(attrs, chain:FALSE);

security_warning(port:port, extra:report);
