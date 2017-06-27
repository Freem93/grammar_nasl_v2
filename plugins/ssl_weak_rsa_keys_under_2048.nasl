#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69551);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/04/10 17:59:31 $");

  script_name(english:"SSL Certificate Chain Contains RSA Keys Less Than 2048 bits");
  script_summary(english:"Checks that the certificate chain has no RSA keys under 2048 bits");

  script_set_attribute(attribute:"synopsis", value:
"The X.509 certificate chain used by this service contains certificates
with RSA keys shorter than 2048 bits.");
  script_set_attribute(attribute:"description", value:
"At least one of the X.509 certificates sent by the remote host has a
key that is shorter than 2048 bits. According to industry standards
set by the Certification Authority/Browser (CA/B) Forum, certificates
issued after January 1, 2014 must be at least 2048 bits.

Some browser SSL implementations may reject keys less than 2048 bits
after January 1, 2014. Additionally, some SSL certificate vendors may
revoke certificates less than 2048 bits before January 1, 2014.

Note that Nessus will not flag root certificates with RSA keys less
than 2048 bits if they were issued prior to December 31, 2010, as the
standard considers them exempt.");
  script_set_attribute(attribute:"see_also", value:"https://www.cabforum.org/Baseline_Requirements_V1.pdf");
  script_set_attribute(attribute:"solution", value:
"Replace the certificate in the chain with the RSA key less than 2048
bits in length with a longer key, and reissue any certificates signed
by the old certificate.");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("ssl_certificate_chain.nasl");
  script_require_keys("SSL/Chain/WeakRSA_Under_2048");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

# Get the port that has weak RSA keys from the KB.
key = "SSL/Chain/WeakRSA_Under_2048";
port = get_kb_item_or_exit(key);
key += "/" + port;

# If the user doesn't want the details, let's stop right here.
if (report_verbosity == 0)
{
  if (get_kb_item("Settings/PCI_DSS")) exit(0, "Reporting for port "+port+" will be done with plugin #73459, pci_dss_ssl_weak_rsa_keys_under_2048.nasl.");

  security_note(port);
  exit(0);
}

# Get the list of certificates with weak RSA keys.
certs = get_kb_list_or_exit(key);

# Add the certificates to the report.
attrs = make_list();

foreach attr (certs)
  attrs = make_list(attrs, attr);

# Report our findings.
report =
  '\n' + 'The following certificates were part of the certificate chain' +
  '\n' + 'sent by the remote host, but contain RSA keys that are considered' +
  '\n' + 'to be weak :' +
  '\n' +
  '\n' + cert_report(attrs, chain:FALSE);

if (get_kb_item("Settings/PCI_DSS")) 
{
  set_kb_item(name:"/tmp/PCI/ssl_weak_rsa_keys/"+port, value:report);
  exit(0, "Reporting for port "+port+" will be done with plugin #73459, pci_dss_ssl_weak_rsa_keys_under_2048.nasl.");
}
else security_note(port:port, extra:report);
