#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10194);
 script_version ("$Revision: 1.21 $");
 script_cvs_date("$Date: 2013/01/25 01:19:09 $");
 
 script_name(english: "HTTP Proxy POST Request Relaying");
 
 script_set_attribute(attribute:"synopsis", value:
"Interactive sessions can be open through the HTTP proxy." );
 script_set_attribute(attribute:"description", value:
"The proxy allows the users to perform POST requests such as

	POST http://cvs.nessus.org:21 

without any Content-length tag.

This request may give an attacker the ability to have an interactive
session.

This problem may allow attackers to go through your firewall, by 
connecting to sensitive ports like 23 (telnet) using your proxy, or it
can allow internal users to bypass the firewall rules and connect to 
ports they should not be allowed to. 

In addition to that, your proxy may be used to perform attacks against
other networks." );
 script_set_attribute(attribute:"solution", value:
"Reconfigure your proxy so that only the users of the internal network 
can use it, and so that it can not connect to dangerous ports (1-1024)." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Determines if we can use the remote web proxy against any port");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2013 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");
 script_dependencie("find_service1.nasl", "proxy_use.nasl");
 script_require_keys("Proxy/usage");
 script_require_ports("Services/http_proxy", 8080);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_kb_item("Services/http_proxy");
if(!port) port = 3128;
if (! get_port_state(port)) exit(0);

usable_proxy = get_kb_item("Proxy/usage");
if (! usable_proxy) exit(0);


rq = http_mk_proxy_request(scheme: "http", method: "POST", item: "/", version: 10, host: get_host_name(), port: 21);
rq['Content-Length'] = NULL;	# Just in case we change the API one day

r = http_send_recv_req(port: port, req: rq);
if (isnull(r)) exit(0);
if (r[0] =~ "^HTTP/1\.[01] (200|503) ") security_warning(port);
