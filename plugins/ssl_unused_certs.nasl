#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3208) exit(0);

include("compat.inc");

if (description)
{
  script_id(56472);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/01/17 17:18:31 $");

  script_name(english:"SSL Certificate Chain Contains Unnecessary Certificates");
  script_summary(english:"Checks that the certificate chain has no extra certificates.");

  script_set_attribute(attribute:"synopsis", value:
"The X.509 certificate chain used by this service contains
certificates that aren't required to form a path to the CA.");
  script_set_attribute(attribute:"description", value:
"At least one of the X.509 certificates sent by the remote host is not
required to form a path from the server's own certificate to the CA. 
This may indicate that the certificate bundle installed with the
server's certificate is for certificates lower in the certificate
hierarchy. 

Some SSL implementations, often those found in embedded devices,
cannot handle certificate chains with unused certificates.");
  script_set_attribute(attribute:"see_also", value:"http://www.ietf.org/rfc/rfc4346.txt");
  script_set_attribute(attribute:"solution", value:
"Remove unnecessary certificates from the certificate chain.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/12");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("ssl_certificate_chain.nasl");
  script_require_keys("SSL/Chain/Unused");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

# Get the port that has unused certificates from the KB.
key = "SSL/Chain/Unused";
port = get_kb_item_or_exit(key);
key += "/" + port;

# If the user doesn't want the details, let's stop right here.
if (report_verbosity == 0)
{
  security_note(port);
  exit(0);
}

# Get the list of certificates that were unused.
certs = get_kb_list_or_exit(key);

# Add unused certificates to the report.
attrs = make_list();
foreach attr (certs)
{
  attrs = make_list(attrs, attr);
}

# Report our findings.
report =
  '\nThe following certificates were part of the certificate chain' +
  '\nsent by the remote host, but are not necessary to building the' +
  '\ncertificate chain.' +
  '\n' +
  '\n' + cert_report(attrs, chain:FALSE);

security_note(port:port, extra:report);
