#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{ 
 script_id(17154);
 script_version ("$Revision: 1.12 $");
 script_cvs_date("$Date: 2013/01/25 01:19:08 $");
 
 script_name(english:"HTTP Proxy CONNECT Loop DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote proxy may be vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The proxy allows the users to perform repeated CONNECT requests to
itself. 

This allow anybody to saturate the proxy CPU, memory or file
descriptors. 

** Note that if the proxy limits the number of connections
** from a single IP (e.g. acl maxconn with Squid), it is 
** protected against saturation and you may ignore this alert." );
 script_set_attribute(attribute:"solution", value:
"Reconfigure your proxy so that it refuses CONNECT requests to itself." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/20");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Connects back to the web proxy through itself"); 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "proxy_use.nasl");
 script_require_keys("Proxy/usage");
 script_require_ports("Services/http_proxy", 8080);
 exit(0);
}

#

port = get_kb_item("Services/http_proxy");
if (!port) port = 8080;
if (! COMMAND_LINE)
{
 proxy_use = get_kb_item("Proxy/usage");
 if (! proxy_use) exit(0);
}
if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

cmd = strcat('CONNECT ', get_host_name(), ':', port, ' HTTP/1.0\r\n\r\n');
for (i = 3; i >= 0; i --)
{
 send(socket:soc, data: cmd);
 repeat 
  line = recv_line(socket:soc, length:4096);
 until (! line || line =~ '^HTTP/[0-9.]+ ');
 if (line !~ '^HTTP/[0-9.]+ +200 ') break;	# Also exit loop on EOF
}

close(soc);
if (i < 0) security_warning(port);
