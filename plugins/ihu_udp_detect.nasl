#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28331);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2012/08/17 18:14:00 $");

  script_name(english:"I Hear U Detection");
  script_summary(english:"Initiates a call via UDP");

 script_set_attribute(attribute:"synopsis", value:
"A VoIP service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is the UDP port for IHU (I Hear U), a voice over IP
application for Linux used to streaming audio between two computers." );
 script_set_attribute(attribute:"see_also", value:"http://ihu.sourceforge.net/" );
 script_set_attribute(attribute:"solution", value:
"Make sure the use of this software is done in accordance with your
organization's security policy.  If this service is unwanted or not
needed, disable it or filter incoming traffic to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/11/27");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = 1793;
if (known_service(port:port, ipproto:"udp")) exit(0);

soc = open_sock_udp(port);
if (!soc) exit(0);


# Ring the remote.
req = "IHU" +                          # HEADER_SYNC_STRING
  mkbyte(0x06) +                       # packet size
  mkbyte(0xff) +                       # info data (IHU_INFO_RING (0x3f) | IHU_INFO_MODE_ULTRAWIDE (0xc0)) 
  mkbyte(0x00);                        # data length
send(socket:soc, data:req);
res = recv(socket:soc, length:1024, min:6);


# If...
if (
  # the response is long-enough and...
  strlen(res) == 6 &&
  # it's a ring reply packet.
  res == "IHU"+mkbyte(0x06)+mkbyte(0x3e)+mkbyte(0x00)
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"udp", proto:"ihu");
  security_note(port:port, proto:"udp");
}

