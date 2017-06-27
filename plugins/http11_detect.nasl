#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(40405);
 script_version ("$Revision: 1.8 $");
 script_cvs_date("$Date: 2012/03/12 17:41:34 $");

 script_name(english:"Web Server Detection (HTTP/1.1)");

 script_set_attribute(attribute:"synopsis", value:
"A web server is running on this port." );
 script_set_attribute(attribute:"description", value:
"The web server on this port responds to HTTP/1.1 requests and appears
to ignore HTTP/1.0 requests, which is unusual." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:
"2009/07/28");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
		 
 script_summary(english: "Sends an HTTP/1.1 request");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 script_copyright(english:"This script is Copyright (C) 2009-2012 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "doublecheck_std_services.nasl", "find_service2.nasl");
 script_require_ports("Services/unknown");
 script_require_keys("Settings/ThoroughTests");
 script_exclude_keys("global_settings/disable_service_discovery");
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");

if (get_kb_item("global_settings/disable_service_discovery"))
 exit(0, "Service discovery is disabled.");

hn = get_host_name(); ip = get_host_ip();

port = get_kb_item_or_exit("Services/unknown"); 
if (! service_is_unknown(port: port))
 exit(0, "The service on port "+port+" is already known.");

# Try hostname
soc = open_sock_tcp(port);
if (! soc) exit(1, "Connection refused to port "+port+".");
send(socket: soc, data: strcat('GET / HTTP/1.1\r\nHost: ', hn, '\r\nConnection: close\r\n\r\n'));
r = recv_line(socket: soc, length: 512);
close(soc);

# Try IP address
if (strlen(r) == 0 && hn != ip)
{
  soc = open_sock_tcp(port);
  if (! soc) exit(1, "Connection refused to port "+port+".");
  send(socket: soc, data: strcat('GET / HTTP/1.1\r\nHost: ', ip, '\r\nConnection: close\r\n\r\n'));
  r = recv_line(socket: soc, length: 512);
  close(soc);
  hn = ip;
}

# Try IP:port
if (strlen(r) == 0)
{
  soc = open_sock_tcp(port);
  if (! soc) exit(1, "Connection refused to port "+port+".");
  hn = strcat(ip, ':', port);
  send(socket: soc, data: strcat('GET / HTTP/1.1\r\nHost: ', hn, '\r\nConnection: close\r\n\r\n'));
  r = recv_line(socket: soc, length: 512);
  close(soc);
}

if (strlen(r) == 0) exit(0, "No answer from port "+port+".");

set_kb_banner(port: port, type: 'get_http11', banner: r);
set_kb_item(name: 'www/'+port+'/http11_hostname', value: hn);

if (r =~ "^HTTP/1\.[01] +[1-5][0-9][0-9]( |$)")
{
  register_service(port: port, proto: "www");
  replace_kb_item(name: 'http/'+port, value: '11');
  security_note(port);
}
