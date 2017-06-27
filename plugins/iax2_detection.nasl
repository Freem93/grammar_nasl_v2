#
# Script Written By Ferdy Riphagen
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#

include("compat.inc");

if (description) {
  script_id(20834);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_name(english:"Inter-Asterisk eXchange Protocol Detection");
  script_summary(english:"Checks if the remote system is running the IAX2 protocol");

  script_set_attribute(attribute:"synopsis", value:
"The remote system is running a server that speaks the Inter-Asterisk
eXchange Protocol.");
  script_set_attribute(attribute:"description", value:
"The Inter-Asterisk eXchange protocol (IAX2) is used by the Asterisk PBX
Server and other IP telephony clients/servers to enable voice
communication between them.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/IAX");
  script_set_attribute(attribute:"solution", value:
"If possible, filter incoming connections to the port so that it is used
by trusted sources only.");
  script_set_attribute(attribute:"risk_factor", value:"None" );

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2006-2017 Ferdy Riphagen");

  script_require_udp_ports(4569);
  exit(0);
}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

port = 4569;
if (!get_udp_port_state(port)) exit(0);

soc = open_sock_udp(port);
if (! soc ) exit(0);

# Generate the 'IAX2' poke packet.
src_call = rand() % 0xff;

poke_msg =
  mkword((1 << 15) | src_call) +       # 'F' bit + source call number
  mkword(0) +                          # 'R' bit + dest call number
  mkdword(0) +                         # timestamp
  mkbyte(0) +                          # OSeqno
  mkbyte(0) +                          # ISeqno
  mkbyte(6) +                          # frametype, 6 => IAX frame
  mkbyte(0x1e);                        # 'C' bit + subclass, 0x1e => POKE request
send(socket:soc, data:poke_msg);
recv = recv(socket:soc, length:128);
if (recv == NULL) exit(0);


# Check if we get the right response.
if (strlen(recv) != 12) exit(0);
if (
  getword(blob:recv, pos:0) > 0x8000 &&
  getword(blob:recv, pos:2) & 0x7fff == src_call &&
  getbyte(blob:recv, pos:10) == 6 &&    # IAX Type
  (
    getbyte(blob:recv, pos:11) == 3 ||  # IAX PONG
    getbyte(blob:recv, pos:11) == 4     # IAX ACK
  )
)
{
  # Register and report the service.
  security_note(port:port, proto:"udp");
  register_service(ipproto:"udp", proto:"iax2", port:port);

  # Be nice and send an ACK to avoid consuming an IAX2 call number.
  callid = getword(blob:recv, pos:0) ^ 0x8000;
  seqo = getbyte(blob:recv, pos:8);
  seqi = getbyte(blob:recv, pos:9);
  ts = getdword(blob:recv, pos:4);

  # Send an ACK.
  ack =
    mkword((1 << 15) | src_call) +     # 'F' bit + source call number
    mkword(callid) +                   # 'R' bit + dest call number
    mkdword(ts) +                      # timestamp
    mkbyte(seqo) +                     # OSeqno
    mkbyte(seqi) +                     # ISeqno
    mkbyte(6) +                        # frametype, 6 => IAX frame
    mkbyte(4);                         # 'C' bit + subclass, 4 => ACK
  send(socket:soc, data:ack);
}
