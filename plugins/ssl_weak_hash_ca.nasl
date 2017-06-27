#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3208 ) exit(0);

include("compat.inc");

if (description)
{
  script_id(95631);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/12/08 18:56:13 $");

  script_cve_id("CVE-2004-2761");
  script_bugtraq_id(11849, 33065);
  script_osvdb_id(45106, 45108, 45127);
  script_xref(name:"CERT", value:"836068");

  script_name(english:"SSL Certificate Signed Using Weak Hashing Algorithm (Known CA)");
  script_summary(english:"Checks signature algorithm used to sign SSL certificates in chain.");

  script_set_attribute(attribute:"synopsis", value:
"A known CA SSL certificate in the certificate chain has been signed
using a weak hashing algorithm.");
  script_set_attribute(attribute:"description", value:
"The remote service uses a known CA certificate in the SSL certificate
chain that has been signed using a cryptographically weak hashing
algorithm (e.g., MD2, MD4, MD5, or SHA1). These signature algorithms
are known to be vulnerable to collision attacks. An attacker can
exploit this to generate another certificate with the same digital
signature, allowing the attacker to masquerade as the affected
service.

Note that this plugin reports all SSL certificate chains signed with
SHA-1 that expire after January 1, 2017 as vulnerable. This is in
accordance with Google's gradual sunsetting of the SHA-1 cryptographic
hash algorithm.");
  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc3279");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/961509");
  script_set_attribute(attribute:"solution", value:
"Contact the Certificate Authority to have the certificate reissued.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ietf:md5");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ietf:x.509_certificate");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssl_certificate_chain.nasl");
  script_require_keys("SSL/Chain/KnownCA/WeakHash");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

# Get the port that has a weak hash algorithm from the KB.
key = "SSL/Chain/KnownCA/WeakHash";
port = get_kb_item_or_exit(key);
key += "/" + port;

# If the user doesn't want the details, let's stop right here.
if (report_verbosity == 0)
{
  security_report_v4(port:port, severity:SECURITY_NOTE);
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
  '\nThe following known CA certificates were part of the certificate' +
  '\nchain sent by the remote host, but contain hashes that are considered' +
  '\nto be weak.' +
  '\n' +
  '\n' + cert_report(attrs, chain:FALSE);

security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
