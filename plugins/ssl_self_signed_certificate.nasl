#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3208 ) exit(0);

include("compat.inc");

if (description)
{
  script_id(57582);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_name(english:"SSL Self-Signed Certificate");
  script_summary(english:"Checks if the certificate chain ends in an unrecognized self-signed certificate");

  script_set_attribute(attribute:"synopsis", value:
"The SSL certificate chain for this service ends in an unrecognized
self-signed certificate.");
  script_set_attribute(attribute:"description", value:
"The X.509 certificate chain for this service is not signed by a
recognized certificate authority.  If the remote host is a public host
in production, this nullifies the use of SSL as anyone could establish
a man-in-the-middle attack against the remote host. 

Note that this plugin does not check for certificate chains that end
in a certificate that is not self-signed, but is signed by an
unrecognized certificate authority.");

  script_set_attribute(attribute:"solution", value:
"Purchase or generate a proper certificate for this service.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");


  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("ssl_certificate_chain.nasl");
  script_require_keys("SSL/Chain/SelfSigned");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

# Get the port that has unused certificates from the KB.
key = "SSL/Chain/SelfSigned";
port = get_kb_item_or_exit(key);
key += "/" + port;

# If the user doesn't want the details, let's stop right here.
if (report_verbosity == 0)
{
  security_warning(port);
  exit(0);
}

# Get the self-signed, unrecognized certificate at the top of the
# certificate chain.
attr = get_kb_item_or_exit(key);

# Add the certificate to the report.
attrs = make_list(attr);

# Report our findings.
report =
  '\nThe following certificate was found at the top of the certificate' +
  '\nchain sent by the remote host, but is self-signed and was not' +
  '\nfound in the list of known certificate authorities :' +
  '\n' +
  '\n' + cert_report(attrs, chain:FALSE);

security_warning(port:port, extra:report);
