#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86067);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/08 18:56:13 $");

  script_name(english:"SSL Certificate Signed Using SHA-1 Algorithm");
  script_summary(english:"Checks signature algorithm used to sign SSL certificates in chain.");

  script_set_attribute(attribute:"synopsis", value:
"An SSL certificate in the certificate chain has been signed using the
SHA-1 hashing algorithm.");
  script_set_attribute(attribute:"description", value:
"The remote service uses an SSL certificate chain that has been signed
with SHA-1, a cryptographically weak hashing algorithm. This signature
algorithm is known to be vulnerable to collision attacks. An attacker
can exploit this to generate another certificate with the same digital
signature, allowing the attacker to masquerade as the affected
service.

Note that this plugin reports all SSL certificate chains signed with
SHA-1 that expire on or between January 1, 2016 and December 31, 2016
as informational. This is in accordance with Google's gradual
sunsetting of the SHA-1 cryptographic hash algorithm.");
  script_set_attribute(attribute:"see_also", value:"http://blog.chromium.org/2014/09/gradually-sunsetting-sha-1.html");
  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc3279");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ssl_certificate_chain.nasl");
  script_require_keys("SSL/Chain/SHA-1:JAN-DEC-16");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

# Get the port that has a weak hash algorithm from the KB.
key = "SSL/Chain/SHA-1:JAN-DEC-16";
port = get_kb_item_or_exit(key);
key += "/" + port;

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

security_note(port:port, extra:report);
