#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25292);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2011/03/11 21:18:08 $");

  script_name(english:"Centennial IP Transfer Agent Detection");
  script_summary(english:"Tries to perform initial handshake with XFERWAN");

 script_set_attribute(attribute:"synopsis", value:
"A network auditing service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service appears to be an IP Transfer Agent used by
Centennial Discovery, or one of its OEM versions.  Discovery is an
enterprise tool for network auditing and monitoring, and the IP
Transfer Agent (XFERWAN) offers a way for client agents and the
application's Control Center to communicate." );
 script_set_attribute(attribute:"see_also", value:"http://www.centennial-software.com/products/discovery/" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/23");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 5003);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(5003);
  if (!port) exit(0);
}
else port = 5003;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Try to initiate a connection.
client = "039156CC-F90DF4DA-1702E29D-7BCC88FB";
magic = 0xedede441;

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
req = 
  crap(data:raw_string(0x00), length:128) +
  client +
  crap(data:raw_string(0x00), length:9);
req = 
  mkdword(magic) +
  mkdword(1) +
  mkdword(16+strlen(req)) +
  mkdword(-1) +
  req;
send(socket:soc, data:req);
res = recv(socket:soc, length:256);
close(soc);


# If the response looks ok...
if (
  strlen(res) == 188 && 
  getdword(blob:res, pos:0) == magic &&
  getdword(blob:res, pos:4) == 5 &&
  substr(res, 0x90, 0xb2) == client
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"xferwan");
  security_note(port);
}
