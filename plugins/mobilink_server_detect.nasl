#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31718);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2011/03/11 21:18:09 $");

  script_name(english:"MobiLink Server Detection");
  script_summary(english:"Simulates a MobiLink Monitor connection");

 script_set_attribute(attribute:"synopsis", value:
"A database synchronization service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is a MobiLink server, a component of the Sybase SQL
Anywhere package used for two-way data synchronization." );
 script_set_attribute(attribute:"see_also", value:"http://www.sybase.com/developer/mobile/sqlanywhere/mobilink" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/01");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 2439);

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
  port = get_unknown_svc(2439);
  if (!port) exit(0);
  if (!silent_service(port)) exit(0); 
}
else port = 2439;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Simulate a new remote management connection.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

from = SCRIPT_NAME;
seq = 1;

req = 
  mkword(1) +
  mkdword(-4) +
  mkbyte(strlen(from)) + from + 
  mkbyte(1);
req = 
  mkword(strlen(req)+5) +              # packet length
  mkword(seq++) +                      # sequence
  mkbyte(3) +                          # constant
  mkword(1) +                          # type
  req;
send(socket:soc, data:req);

req = mkword(5) + 
  mkword(seq++) +
  mkbyte(3) + 
  mkword(0x0c);
send(socket:soc, data:req);

res = recv(socket:soc, length:0x17);
close(soc);


# If the result looks right...
if (
  strlen(res) == 0x17 &&
  stridx(res, raw_string(0x0e, 0x00, 0x01, 0x00, 0x03)) == 0 &&
  stridx(res, raw_string(0x06, "MLServ")) == 9 &&
  stridx(res, raw_string(0x05, 0x00, 0x02, 0x00, 0x03)) == 0x10
)
{
  # Register and report the service.
  register_service(port:port, proto:"mobilink");
  security_note(port);
}
