#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) 
{

  script_id(49793);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2011/03/11 21:18:07 $");

  script_name(english:"Apple Remote Events Service Detection");
  script_summary(english:"Detects the Apple Remote Events Service"); 
 
  script_set_attribute(
    attribute:"synopsis",
    value:"A remote events service is listening on the remote host."
  );

  script_set_attribute(
    attribute:"description", 
    value:
"The remote service is the Apple Remote Events Service, a remote
events service that allows your computer to respond to events sent
from other computers and interact with them on a network."
  );

  script_set_attribute(
    attribute:"see_also", 
    value:"http://docs.info.apple.com/article.html?path=Mac/10.4/en/mh896.html"
  );

  script_set_attribute(
    attribute:"see_also", 
    value:"http://docs.info.apple.com/article.html?path=Mac/10.5/en/8418.html"
  );

  script_set_attribute(
    attribute:"see_also", 
    value:"http://docs.info.apple.com/article.html?path=Mac/10.6/en/8418.html"
  );

  script_set_attribute(
    attribute:"solution", 
    value:"Limit incoming traffic to this port if desired."
  );

  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports(3031);

  exit(0);

}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

port = 3031;
if (known_service(port:port)) exit(0, "The service listening on TCP port "+port+" is already known.");
if (!get_tcp_port_state(port)) exit(0, "TCP port "+port+" is not open."); 

soc = open_sock_tcp(port);
if (!soc) exit(1, "Failed to open a socket on port "+port+"."); 


# 44 6d 64 54 00 00 00 17 00 00 00 01 00 00 00 00 11 11 00 ff 01 ff 13
are_detect_req  = raw_string(0x44, 0x6d, 0x64, 0x54, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0x00, 0xff, 0x01, 0xff, 0x13);

# 44 6d 64 54 00 00 00 17 00 00 00 01
are_detect_recv = raw_string(0x44, 0x6d, 0x64, 0x54, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x01);

# we send 'are_detect_req', we expect to receive 'are_detect_recv'
send(socket:soc, data:are_detect_req);

detect_data = recv(socket:soc, length:1024, min:12);
if (strlen(detect_data) == 0) exit(0, "The service listening on TCP port "+port+" did not respond.");

if (are_detect_recv><detect_data)
{
  register_service(port:port, proto:"apple_remote_events");
  security_note(port:port);
}
else exit(0, "Apple Remote Events service was not detected on port"+port+".");
