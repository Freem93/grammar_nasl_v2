#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25422);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2011/03/11 21:18:09 $");

  script_name(english:"SNMPc Management Server Detection");
  script_summary(english:"Tries to login to SNMPc Management Server");

 script_set_attribute(attribute:"synopsis", value:
"A network management service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service appears to be an SNMPc Management Server instance,
which is used by the SNMPc application for remote network management." );
 script_set_attribute(attribute:"see_also", value:"http://www.castlerock.com/products/snmpc/default.php" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/05");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SNMP");
  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 165);
  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
  port = get_unknown_svc(165);
  if (!port) exit(0);
}
else port = 165;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


user = SCRIPT_NAME;
pass = "nessus";
seq = rand() % 0xffff;
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);


# Initiate a connection
init = 
  mkword(seq) + 
  mkword(0x00) +
  mkbyte(0x51) +
  mkbyte(0x03) +
  mkword(0x00) +
  mkdword(0x02) +
  "rcon";
init = mkdword(strlen(init) + 4) + init;
send(socket:soc, data:init);
res = recv(socket:soc, length:1024);


# If the response looks ok...
if (
  # the word at the first byte is the packet length and...
  (strlen(res) > 4 && getdword(blob:res, pos:0) == strlen(res)) &&
  # the word at position 4 is our sequence number and...
  getword(blob:res, pos:4) == seq &&
  # it has -1 (dword) at position 8
  getdword(blob:res, pos:8) == 0xffffffff
) 
{
  # Try to log in.
  seq += 1;
  req = 
    mkword(seq) + 
    mkword(0x00) +
    mkbyte(0x52) +
    mkbyte(0x03) +
    mkword(0x00) +
    mkdword(0x02) +
    user + mkbyte(0x09) +
    pass + mkbyte(0x09) +
    mkword(0x30);
  req = mkdword(strlen(req) + 4) + req;
  send(socket:soc, data:req);
  res = recv(socket:soc, length:1024);

  if (
    # the word at the first byte is the packet length and...
    (strlen(res) > 4 && getdword(blob:res, pos:0) == strlen(res)) &&
    # the word at position 4 is our sequence number and...
    getword(blob:res, pos:4) == seq &&
    # it has -1 (dword) at position 8
    getdword(blob:res, pos:8) == -1
  ) 
  {
    # Register and report the service.
    register_service(port:port, ipproto:"tcp", proto:"crserv");
    security_note(port);
  }
}


close(soc);
