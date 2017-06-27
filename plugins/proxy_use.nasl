#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10195);
 script_version("$Revision: 1.42 $");
 script_cvs_date("$Date: 2014/04/25 17:36:44 $");

 script_name(english:"HTTP Proxy Open Relay Detection");
 script_summary(english:"Determines if we can use the remote web proxy");
 
 script_set_attribute(attribute:"synopsis", value:"The remote web proxy server accepts requests.");
 script_set_attribute(attribute:"description", value:
"The remote web proxy accepts unauthenticated HTTP requests from the
Nessus scanner.  By routing requests through the affected proxy, a user
may be able to gain some degree of anonymity while browsing websites,
which will see requests as originating from the remote host itself
rather than the user's host.");
 script_set_attribute(attribute:"solution", value:"Make sure access to the proxy is limited to valid users / hosts.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");

 script_dependencie("find_service1.nasl", "httpver.nasl", "broken_web_server.nasl");
 script_require_ports("Services/http_proxy", "Services/www", 80, 3128, 8080);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports = make_list();
kb_list = get_kb_list("Services/http_proxy");
if (!isnull(kb_list)) ports = make_list(kb_list);

kb_list = get_kb_list("Services/www");
if (!isnull(kb_list))
{
  foreach p (kb_list)
  {
    if (get_kb_item("Services/www/"+p+"/working"))
    {
      ports = add_port_in_list(list:ports, port:p);
    }
  }
}

foreach p (make_list(80, 3128, 8080))
{
  if (get_port_state(p) && service_is_unknown(port:p))
  {
    ports = add_port_in_list(list:ports, port:p);
  }
}

proxy_found = 0;
foreach port (ports)
{
  rq = http_mk_proxy_request(method:"GET", scheme:"http", host:"rfi.nessus.org", item:"/check_proxy.html", version:10);
  r = http_send_recv_req(port:port, req:rq);
  if (! isnull(r) && r[0] =~ "^HTTP/1\.[01] 200 " && "@NESSUS:OK@" >< r[2])
  {
    security_note(port);

    set_kb_item(name:"Proxy/usage", value:TRUE);
    set_kb_item(name:"Services/http_proxy", value:port);

    proxy_found++;
  }
}
if (!proxy_found) exit(0, "The host does not appear to be running an HTTP proxy.");
