#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) 
{

  script_id(45436);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2011/08/26 19:54:55 $");

  script_name(english:"Logitech Touch Mouse Server Detection");
  script_summary(english:"Detects a Logitech Touch Mouse Server"); 
 
  script_set_attribute(
    attribute:"synopsis",
    value:"A remote control service is listening on the remote host."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote service appears to be a Logitech Touch Mouse Server, a
remote control application that allows a remote client to control the
keyboard and mouse functions of the server. 

Note that version 1.0 of this service does not implement any sort of
access control, which could be exploited by an unauthenticated, remote
attacker to execute arbitrary programs or otherwise control the server
remotely."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.logitech.com/index.cfm/494/6367&cl=US,EN"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?84255377"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Limit incoming traffic to this port if desired."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/04/07");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 4026);

  exit(0);

}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


# nb: port number is not configurable.
port = 4026;
if (known_service(port:port)) exit(0, "The service is already known on port "+port+".");

if (!get_tcp_port_state(port)) exit(0, "Port "+port+" is not open.");
if (!get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");

soc2 = open_sock_udp(port);
if (!soc2) exit(1, "Can't open socket on UDP port "+port+".");

req = mkdword(0x00) + mkdword(0x00) + mkdword(0) + mkdword(0x00);
send(socket:soc2, data:req);

sleep(1);

res = recv(socket:soc, length:32, min:16);
if (strlen(res) == 0) exit(0, "The service on port "+port+" failed to respond.");

if (req == res)
{
  register_service(port:port, ipproto:"tcp", proto:"logitech_touch_ms");
  security_note(port);

  register_service(port:port, ipproto:"udp", proto:"logitech_touch_ms");
  security_note(port:port, proto:"udp");
}
else exit(0, "The service on port "+port+" does not appear to be Logitech's Touch Mouse Server.");
