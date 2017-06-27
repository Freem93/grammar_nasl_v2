#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31679);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2011/03/11 21:18:10 $");

  script_name(english:"XSTUNT Server Detection");
  script_summary(english:"Starts to register a client");

 script_set_attribute(attribute:"synopsis", value:
"A service for TCP NAT traversal is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is an XSTUNT server.  XSTUNT is a variation on
STUNT (Simple Traversal of UDP Through NATs and TCP too), which
extends STUN to include TCP functionality." );
 script_set_attribute(attribute:"see_also", value:"http://www.cis.nctu.edu.tw/~gis87577/xDreaming/XSTUNT/index.html" );
 script_set_attribute(attribute:"solution", value:
"Make sure use of this program fits with your corporate security
policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/26");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 8123);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(8123);
  if (!port) exit(0);
  if (silent_service(port)) exit(0); 
}
else port = 8123;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Read the banner and make sure it's 12 bytes.
res = recv(socket:soc, length:16, min:12);
if (strlen(res) != 12) exit(0);


# Send a client id and read the response.
id = string("nessus-", unixtime());
req = id + crap(data:" ", length:32-strlen(id));
send(socket:soc, data:req);
res = recv(socket:soc, length:64, min:56);


# If...
if (
  # the packet size looks right and...
  strlen(res) == 56 &&
  # it starts with our client id
  stridx(res, req) == 0
)
{
  # Register / report the service.
  register_service(port:port, proto:"xstunt");
  security_note(port);
}
