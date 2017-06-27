#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3208 ) exit(0);

include("compat.inc");

if (description)
{
  script_id(83298);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/05/08 21:57:23 $");

  script_name(english:"SSL Certificate Chain Contains Certificates Expiring Soon");
  script_summary(english:"Detects SSL certificate chains with certificates expiring soon.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an SSL certificate chain with one or more
certificates that are going to expire soon.");
  script_set_attribute(attribute:"description", value:
"The remote host has an SSL certificate chain with one or more SSL
certificates that are going to expire soon. Failure to renew these
certificates before the expiration date may result in denial of
service for users.");
  script_set_attribute(attribute:"solution", value:
"Renew any soon to expire SSL certificates.");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/08");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("ssl_certificate_chain.nasl");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

global_var port, singular;

function make_report()
{
  local_var attr, attrs, certs, key;

  key = _FCT_ANON_ARGS[0];

  # Get the list of certificates that were unused.
  certs = get_kb_list("SSL/Chain/" + key + "/" + port);
  if (isnull(certs))
    return NULL;

  attrs = make_list();
  foreach attr (certs)
  {
    attrs = make_list(attrs, attr);
  }

  singular = (max_index(attrs) == 1);

  return cert_report(attrs, chain:FALSE);
}

report_out = "";

ports = get_kb_list_or_exit("SSL/Chain/Future_Expiry/After/*");
port = branch(keys(ports));

port -= "SSL/Chain/Future_Expiry/After/";

# Report certificates that have a 'not after' date in the past.
report = make_report("Future_Expiry/After");
if (report)
{
  if (singular)
  {
    report_out +=
      '\nThe following soon to expire certificate was part of the certificate' +
      '\nchain sent by the remote host :';
  }
  else
  {
    report_out +=
      '\nThe following soon to expire certificates were part of the' +
      '\ncertificate chain sent by the remote host :';
  }

  report_out +=
    '\n' +
    '\n' + report;

  security_note(port:port, extra:report_out);
}
else audit(AUDIT_HOST_NOT, "affected"); 
