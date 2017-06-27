#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22877);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2011/03/11 21:18:09 $");

  script_name(english:"Skinny Server Detection");
  script_summary(english:"Detects a Skinny server");

 script_set_attribute(attribute:"synopsis", value:
"The remote server supports the Skinny protocol." );
 script_set_attribute(attribute:"description", value:
"The remote server is an H.323 proxy that understands the Skinny
protocol, also known as SCCP, for 'Skinny Client Control Protocol'. 
Skinny is Cisco's proprietary lightweight terminal control protocol
used by some VoIP phones to communicate with Cisco CallManager or
Asterisk PBX systems." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Skinny_Client_Control_Protocol" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/10/19");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 2000);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) {
  port = get_unknown_svc(2000);
  if (!port) exit(0);
}
else port = 2000;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Try to register a device.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
device = "SEP6E6573737573";            # must be 15 chars!
ip = split(this_host(), sep:'.', keep:FALSE);
sport = get_source_port(soc);

# - start with an alarm message; server won't respond. 
req = mkdword(96) +                    # message length
  mkdword(0) +                         # reserved
  mkdword(0x20) +                      # message id (0x20 => alarm)
    mkdword(2) +                       #   alarm severity (2 => informational)
    "Name=" + device + "  Load=F2.02  Parms=Status/IPaddr" +   #   display message
      crap(length:27, data:raw_string(0)) +
    mkdword(0x65) +                    #   alarm param 1
    mkbyte(int(ip[0])) +               #   alarm param 2
      mkbyte(int(ip[1])) + 
      mkbyte(int(ip[2])) + 
      mkbyte(int(ip[3]));
send(socket:soc, data:req);

# - then send the actual station register along with an IP port message.
req = mkdword(40) +                    # message length
  mkdword(0) +                         # reserved
  mkdword(1) +                         # message id (1 => station register)
    device + mkbyte(0) +               #   name
    mkdword(0) +                       #   station userid
    mkdword(1) +                       #   station instance
    mkbyte(int(ip[0])) +               #   client ip
      mkbyte(int(ip[1])) + 
      mkbyte(int(ip[2])) + 
      mkbyte(int(ip[3])) + 
    mkdword(2) +                       #   device type (2 => 12SPplus)
    mkdword(0) +                       #   max streams
  mkdword(8) +                         # message length
  mkdword(0) +                         # reserved
  mkdword(2) +                         # message id (2 => IP port)
    mkbyte(sport >> 8) + mkbyte(sport & 0xff) +   # source port
    mkword(0);
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);


# It understands Skinny if...
if (
  # the responds has room for at least a message id and...
  strlen(res) > 12 && 
  # the initial dword equals the message length and...
  getdword(blob:res, pos:0) == strlen(res) - 8 &&
  (
    # we received an ack or
    getdword(blob:res, pos:8) == 0x81 ||
    # either we're rejected as not being authorized
    (getdword(blob:res, pos:8) == 0x9d && string("No Authority: ", device) >< res)
  )
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"skinny");
  security_note(port);
}
