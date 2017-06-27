#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42980);
 script_version ("$Revision: 1.8 $");
 script_cvs_date("$Date: 2012/04/02 16:34:10 $");

 script_name(english:"SSL Certificate Expiry - Future Validity");
 script_summary(english:"Checks SSL certificate expiry");

 script_set_attribute(
  attribute:'synopsis',
  value:
"There is a problem with the SSL certificate associated with the
remote service."
 );
 script_set_attribute(
  attribute:'description',
  value:
"The SSL certificate for the remote SSL-enabled service is not yet
valid."
 );
 script_set_attribute(
  attribute:"solution", 
  value:
"Make sure that system clock on the Nessus Server host is not out of
sync.  If it's not, then purchase or generate a new SSL certificate to
replace the existing one."
 );
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/02");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2012 Tenable Network Security, Inc.");
 script_family(english:"General");

 script_dependencies("ssl_cert_expiry.nasl");
 script_require_keys("SSL/Supported");

 exit(0);
}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

get_kb_item_or_exit("SSL/Supported");

# Get list of ports that use SSL or StartTLS.
ports = get_ssl_ports();
if (isnull(ports) || max_index(ports) == 0)
  exit(1, "The host does not appear to have any SSL-based services.");

foreach port (ports)
{
  if (!get_port_state(port)) continue; 

  future_valid_date = get_kb_item('Transport/SSL/'+port+'/future_validity_date');

  if (!isnull(future_valid_date))
  {
    if (report_verbosity > 0)
    {
      issuer = get_kb_item('Transport/SSL/'+port+'/issuer');
      subject = get_kb_item('Transport/SSL/'+port+'/subject');

      valid_start_alt = future_valid_date;
      valid_start_end = get_kb_item('Transport/SSL/'+port+'/valid_start_end');

      report = 
        '\n' + 'The SSL certificate is not valid before ' + future_valid_date + ' :' +
        '\n' + 
        '\n  Subject          : ' + subject +
        '\n  Issuer           : ' + issuer +
        '\n  Not valid before : ' + valid_start_alt +
        '\n  Not valid after  : ' + valid_end_alt + '\n';
      security_note(port:port, extra:report);
    }
    else security_note(port);
  }
}
