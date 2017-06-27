#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42981);
 script_version ("$Revision: 1.8 $");
 script_cvs_date("$Date: 2012/04/02 16:34:10 $");

 script_name(english:"SSL Certificate Expiry - Future Expiry");
 script_summary(english:"Checks SSL certificate expiry");

 script_set_attribute(
  attribute:'synopsis',
  value:
"The SSL certificate associated with the remote service will expire
soon."
 );
 script_set_attribute(
  attribute:'description',
  value:
"The SSL certificate associated with the remote service will expire
soon."
 );
 script_set_attribute(
  attribute:"solution", 
  value:
"Purchase or generate a new SSL certificate in the near future to
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

  if (get_kb_item('Transport/SSL/'+port+'/expired_cert')) continue;

  days_left   = get_kb_item('Transport/SSL/'+port+'/days_to_expire');
  expiry_date = get_kb_item('Transport/SSL/'+port+'/future_expiry_date');

  if (!isnull(days_left) && !isnull(expiry_date))
  {
    if (report_verbosity > 0)
    {
      issuer = get_kb_item('Transport/SSL/'+port+'/issuer');
      subject = get_kb_item('Transport/SSL/'+port+'/subject');

      valid_start_alt = get_kb_item('Transport/SSL/'+port+'/valid_start_alt');
      valid_end_alt = expiry_date;

      report = 
        '\n' + 'The SSL certificate will expire within ' +  days_left + ' days, at' + 
        '\n' + expiry_date + ' :' +
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
