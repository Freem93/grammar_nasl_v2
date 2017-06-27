#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3208) exit(0);

include("compat.inc");

if (description)
{
  script_id(60108);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_name(english:"SSL Certificate Chain Contains Weak RSA Keys");
  script_summary(english:"Checks that the certificate chain has no weak RSA keys");

  script_set_attribute(attribute:"synopsis", value:
"The X.509 certificate chain used by this service contains certificates
with RSA keys shorter than 1024 bits.");
  script_set_attribute(attribute:"description", value:
"At least one of the X.509 certificates sent by the remote host has a
key that is shorter than 1024 bits.  Such keys are considered weak due
to advances in available computing power decreasing the time required to
factor cryptographic keys.

Some SSL implementations, notably Microsoft's, may consider this SSL
chain to be invalid due to the length of one or more of the RSA keys it
contains.");
  script_set_attribute(attribute:"solution", value:
"Replace the certificate in the chain with the weak RSA key with a
stronger key, and reissue any certificates it signed.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f460485a");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7949cc5f");


  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/24");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("ssl_certificate_chain.nasl");
  script_require_keys("SSL/Chain/WeakRSA_Under_1024");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

# Get the port that has weak RSA keys from the KB.
key = "SSL/Chain/WeakRSA_Under_1024";
port = get_kb_item_or_exit(key);
key += "/" + port;

# If the user doesn't want the details, let's stop right here.
if (report_verbosity == 0)
{
  security_warning(port);
  exit(0);
}

# Get the list of certificates with weak RSA keys.
certs = get_kb_list_or_exit(key);

# Add the certificates to the report.
attrs = make_list();
foreach attr (certs)
{
  attrs = make_list(attrs, attr);
}

# Report our findings.
report =
  '\nThe following certificates were part of the certificate chain' +
  '\nsent by the remote host, but contain RSA keys that are considered' +
  '\nto be weak.' +
  '\n' +
  '\n' + cert_report(attrs, chain:FALSE);

security_warning(port:port, extra:report);
