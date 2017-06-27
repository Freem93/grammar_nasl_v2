#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3208 ) exit(0);

include("compat.inc");

if (description)
{
  script_id(94761);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/11/14 14:53:50 $");

  script_name(english:"SSL Root Certification Authority Certificate Information");
  script_summary(english:"Checks root certification authority certificate.");

  script_set_attribute(attribute:"synopsis", value:
"A root Certification Authority certificate was found at the top of the
certificate chain.");
  script_set_attribute(attribute:"description", value:
"The remote service uses an SSL certificate chain that contains a
self-signed root Certification Authority certificate at the top of the
chain.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/cc778623");
  script_set_attribute(attribute:"solution", value:
"Ensure that use of this root Certification Authority certificate
complies with your organization's acceptable use and security
policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ietf:md5");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ietf:x.509_certificate");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssl_certificate_chain.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

get_kb_item_or_exit("SSL/Supported");

# Get list of all ports that ssl_certificate_chain.nasl ran against
keys = keys(get_kb_list_or_exit("SSL/ValidCAChain/*"));

# Branch on the ports
key = branch(keys);
port = key - 'SSL/ValidCAChain/';

# Pull information about the certificate at the top of the chain
# These are set to TRUE or FALSE by ssl_certificate_chain.nasl
top_ca = get_kb_item_or_exit("SSL/Chain/Top/"+port+"/CA");
top_ss = get_kb_item_or_exit("SSL/Chain/Top/"+port+"/Self-Signed");

# Certificate has the CA extension but is not self-signed
if (top_ca && !top_ss)
  exit(0, "The certificate at the top of the chain on port "+port+" is an intermediate CA certificate with an unknown issuer.");

# Certificate does not have the CA extension and is not self-signed
if (!top_ca && !top_ss)
  exit(0, "The certificate at the top of the chain on port "+port+" is a server certificate with an unknown issuer.");

# Certificate does not have the CA extension but is self-signed
if (!top_ca && top_ss)
  exit(0, "The certificate at the top of the chain on port "+port+" is a self-signed server certificate.");

# If we got this far, the certificate at the top of the chain is a
# self-signed CA certificate - a root CA certificate.
# That means that either the SSL service provided the root CA certificate
# as part of the chain, or we were able to find the root CA certificate
# to complete the chain in known_CA.inc or a list of custom CAs.

# We will have saved the root CA certificate info
key    = "SSL/Chain/Root/" + port;
attr   = get_kb_item_or_exit(key);
attrs  = make_list(attr);

report =
  '\nThe following root Certification Authority certificate was found :' +
  '\n' +
  '\n' + cert_report(attrs, chain:FALSE);

security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
