#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(11022);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_name(english:"eDonkey Detection");
  script_summary(english:"Sends eDonkey HELLO / LOGINREQUEST");

 script_set_attribute(attribute:"synopsis", value:
"There is a peer-to-peer file sharing application listening on the
remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running eDonkey or one of its variants,
which is commonly used for sharing music, films, and software." );
 script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/EDonkey_network" );
 script_set_attribute(attribute:"solution", value:
"Make sure this service agrees with your organization's security
and acceptable use policies." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/08");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 4662);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
  port = get_unknown_svc(4662);
  if (!port) exit(0);
}
else port = 4662;
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a hello / login packet and read the response.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
pkt = 
  mkbyte(1) +                          # OP_HELLO / OP_LOGINREQUEST
  mkbyte(16) + MD4("nessus") +         # client hash
  mkdword(0) +                         # our IP (ok, I lied :-)
  mkword(port) +                       # client port
  mkdword(2) +                         # number of tags
    mkbyte(2) +                        #   tag type 2
      mkword(1) +                      #     tag name size
      mkbyte(1) +                      #     tag name (nick)
      mkword(6) + "nessus" +           #     tag value
    mkbyte(3) +                        #   tag type 3
      mkword(1) +                      #     tag name size
      mkbyte(11) +                     #     tag name (version)
      mkdword(60) +                    #     tag value
   mkdword(0) +                        # server IP
   mkword(0);                          # server port
send(socket:soc, data:mkbyte(0xe3) + mkdword(strlen(pkt)) + pkt);
res = recv(socket:soc, length:1024);
close(soc);
if (isnull(res)) exit(0);


# It's an eDonkey client/server if...
if (
  # the protocol is eDonkey 2000 or eMule extended and...
  (getbyte(blob:res, pos:0) == 0xe3 || getbyte(blob:res, pos:0) == 0xc5) &&
  # it's a HELLO ANSWER and...
  getbyte(blob:res, pos:5) == 0x4c &&
  # the message length agrees with the size of the response.
  getdword(blob:res, pos:1) + 5 == strlen(res)
)
{
  register_service(port:port, proto:"eDonkey");

  # Extract some interesting info for the report.
  info = "";
  i = stridx(res, raw_string(0x02, 0x01, 0x00, 0x01), 32);
  if (i >= 0)
  {
    l = getword(blob:res, pos:i+4);
    info += "  Server name   : " + substr(res, i+6, i+6+l-1) + '\n';
  }
  i = stridx(res, raw_string(0x03, 0x01, 0x00, 0xf9), 32);
  if (i >= 0)
  {
    # Kademlia network.
    kadudpport = getword(blob:res, pos:i+4);
    if (kadudpport) info += "  KAD UDP port  : " + kadudpport + '\n';
    # eDonkey 2K.
    ed2kudpport = getword(blob:res, pos:i+6);
    if (ed2kudpport) info += "  ED2K UDP port : " + ed2kudpport + '\n';
  }

  if (report_verbosity && info) security_note(port:port, extra:'\n'+info);
  else security_note(port);
}
