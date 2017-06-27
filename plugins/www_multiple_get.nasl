#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(18366);
 script_version ("$Revision: 1.9 $");

 script_name(english: "Web Server GET Request Saturation Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server appears to be using anti-DoS countermeasures." );
 script_set_attribute(attribute:"description", value:
"The remote web server shuts down temporarily or blacklists us when it
receives several GET HTTP/1.0 requests in a row.

This might trigger false positives in generic destructive or DoS 
plugins.

** Nessus enabled some countermeasures, however they might be 
** insufficient." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/25");
 script_cvs_date("$Date: 2011/03/14 21:48:16 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english: "Several GET requests in a row temporarily shut down the web server");
 # It is not really destructive, but it is useless in safe_checks mode
 script_category(ACT_DESTRUCTIVE_ATTACK); 
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 1);

# CISCO IP Phone 7940 behaves correctly on a HTTP/1.1 request,
# so we forge a crude HTTP/1.0 request. 
# r = http_get(port: port, item: '/'); 
r = 'GET / HTTP/1.0\r\n\r\n';
max = 12;

for (i = 0; i < max; i ++) 
{
 w = http_send_recv_buf(port: port, data: r, exit_on_fail: 0);
 if (isnull(w)) break;
}

debug_print('i=', i, '\n');
if (i == 0)
 exit(1, "The web server on port "+port+" never answered.");
else if (i < max)
{
 debug_print('Web server rejected connections after ', i, ' connections\n');
 set_kb_item(name: 'www/multiple_get/'+port, value: i);
 if (report_verbosity > 1)	# Verbose report
  security_note(port);
}
