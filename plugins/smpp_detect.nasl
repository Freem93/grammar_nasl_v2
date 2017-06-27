#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31132);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2012/04/12 18:29:36 $");

  script_name(english:"SMPP Server Detection");
  script_summary(english:"Sends an ENQUIRE_LINK request");

 script_set_attribute(attribute:"synopsis", value:
"A messaging service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service supports the Short Message Peer-to-Peer (SMPP)
protocol, a messaging protocol designed for exchanging a high volume
of SMS messages." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/SMPP" );
 script_set_attribute(attribute:"see_also", value:"http://smsforum.net/" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/21");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2012 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 2775);

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
  port = get_unknown_svc(2775);
  if (!port) exit(0);
  # nb: a server isn't necessarily silent.
}
else port = 2775;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send an ENQUIRE_LINK request.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

seq = rand() % 0xffff;

req = mkdword(0x15) +                  # command id (0x15 => enquire_link)
      mkdword(0) +                     # command status
      mkdword(seq);                    # sequence #
req = mkdword(strlen(req)+4) + req;
send(socket:soc, data:req);
res = recv(socket:soc, length:64, min:16);
close(soc);


# Register / report the service if it looks like an ENQUIRE_LINK_RESP.
if (
  strlen(res) == 16 && 
  getdword(blob:res, pos:4) == (0x80000000 | 0x15) && 
  getdword(blob:res, pos:12) == seq
)
{
  register_service(port:port, proto:"smpp");
  security_note(port);
}
