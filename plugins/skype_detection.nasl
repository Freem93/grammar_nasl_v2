#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(19772);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2012/07/30 21:34:43 $");

 script_name(english:"Skype Detection");

 script_set_attribute(attribute:"synopsis", value:
"A Voice-Over-IP service is running on the remote port." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Skype, a peer-to-peer Voice-Over-IP application.

Due to the peer-to-peer nature of Skype, any user connecting to the
Skype network may consume a large amount of bandwidth. 

Make sure the use of this program is done in accordance with your corporate
security policy." );
 script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it. Note that filtering this port will
not be sufficient, since this software can establish outgoing connections." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/22");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:skype:skype");
script_end_attributes();

 script_summary(english:"Skype detection");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencie("find_service1.nasl", "embedded_web_server_detect.nasl");
 script_require_ports("Services/www");
 exit(0);
}


# start script
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 80, embedded: TRUE, dont_break: 1);

banner = get_http_banner(port:port);
if ( "Server:" >< banner )
 exit(0, "The web server on port "+port+" sends a Server header.");

res = http_get_cache(item:"/", port:port, exit_on_fail: 1);
if ( res !~ "HTTP/1\..* 404 Not Found" )
 exit(0, "GET / on port "+port+" did not return 404.");


soc = open_sock_tcp(port);
if ( ! soc ) exit(1, "Connection refused on port "+port+".");
skype_hello  = raw_string(0xec, 0x42, 0x55, 0xa8, 
		    0xfb, 0x05, 0x58, 0x29, 
		    0x32, 0xcf, 0x0d, 0x0a, 
		    0x0d, 0x0a);

send(socket:soc, data:skype_hello);
r = recv(socket:soc, length:1024, min:14);
if ( ! r || strlen(r) < 14 ) exit(0, "Short read on port "+port+".");

close(soc);

e = 0;
for ( i = 0 ; i < 14 ; i ++ )
 if ( ord(r[i]) < ord("!") || ord(r[i]) > ord("~") ) e ++;

if ( e >= 3 )
{
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(1, "Connection refused on port "+port+".");
 send(socket:soc, data:skype_hello);
 r2 = recv(socket:soc, length:4096, min:strlen(r));
 if ( r2 != r ) {
	security_note(port);
	register_service(port:port, proto:"skype");
	# Skype is not a web server
	declare_broken_web_server(port: port, reason: 'Skype is not a real server\n');
	}
}
