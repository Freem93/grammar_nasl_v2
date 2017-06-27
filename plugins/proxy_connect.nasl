#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{ 
 script_id(10192);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2016/04/27 20:37:47 $");
 
 script_name(english:"HTTP Proxy CONNECT Request Relaying");
 script_summary(english:"Determines if we can use the remote web proxy against any port.");
 
 script_set_attribute(attribute:"synopsis", value:
"An HTTP proxy running on the remote host can be used to establish
interactive sessions.");
 script_set_attribute(attribute:"description", value:
"The proxy allows users to perform CONNECT requests such as :

	CONNECT http://cvs.example.org:23 

This request gives the person who made it the ability to have an
interactive session with a third-party site. 

This issue may allow attackers to bypass your firewall by connecting
to sensitive ports such as 23 (telnet) via the proxy, or it may allow
internal users to bypass the firewall rules and connect to ports or
sites they should not be allowed to. 

In addition, your proxy may be used to perform attacks against other
networks.");
 script_set_attribute(attribute:"solution", value:
"Reconfigure your proxy to refuse CONNECT requests.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");

 script_dependencie("find_service1.nasl", "proxy_use.nasl", "httpver.nasl");
 script_require_keys("Proxy/usage");
 script_require_ports("Services/http_proxy", 8080);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports = make_list();
kb_list = get_kb_list("Services/http_proxy");
if (!isnull(kb_list)) ports = make_list(kb_list);

foreach p (make_list(8080))
{
  if (get_port_state(p) && service_is_unknown(port:p))
  {
    ports = add_port_in_list(list:ports, port:p);
  }
}

proxy_found = 0;
foreach port (list_uniq(ports))
{
  rq = http_mk_proxy_request(method:"CONNECT", host:get_host_name(), port:1234, version:10);
  r = http_send_recv_req(port:port, req:rq);
  if (!isnull(r))
  {
    if (r[0] =~ "^HTTP/1\.[01] (200|403|503) ")
    {
      security_note(port);
      proxy_found++;
    }
  }
}
if (!proxy_found) exit(0, "The host does not appear to be running an HTTP proxy that supports CONNECT requests.");
