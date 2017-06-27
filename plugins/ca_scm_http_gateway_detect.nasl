#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33140);
  script_version("$Revision: 1.6 $");

  script_name(english:"CA Secure Content Manager HTTP Gateway Service Detection");
  script_summary(english:"Sends a request for a forbidden URL");

 script_set_attribute(attribute:"synopsis", value:
"A web proxy is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is the HTTP Gateway Service component of Computer
Associates' Secure Content Manager, which is used to filter web
traffic." );
 script_set_attribute(attribute:"see_also", value:"http://www.ca.com/us/products/product.aspx?id=4673" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/11");
 script_cvs_date("$Date: 2011/03/14 21:48:02 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl", "http_version.nasl");
  script_require_ports("Services/unknown", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(8080);
  if (!port) exit(0);
  if (!silent_service(port)) exit(0); 
}
else port = 8080;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);

# Send a request that should be blocked.
rq = http_mk_proxy_request(method:"CONNECT", host: "localhost", port: 445);
r = http_send_recv_req(port: port, req: rq);
if (isnull(r)) exit(0);

res = strcat(r[0], r[1], '\r\n', r[2]);

# Check the response for evidence of SCM.
if (
  "403 Access Denied" >< res &&
  "SCM has cancelled the attempt to tunnel" >< res &&
  "Secure Content Manager" >< res
)
{
  # Register and report the service.
  register_service(port:port, proto:"http_proxy");
  security_note(port);
}
