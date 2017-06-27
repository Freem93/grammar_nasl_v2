#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34364);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2011/03/11 21:18:10 $");

  script_name(english:"Zebedee Server Detection");
  script_summary(english:"Sends a request to establish a tunnel");

 script_set_attribute(attribute:"synopsis", value:
"A tunneling service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Zebedee in server mode, which allows for
securely tunneling TCP and UDP connections to arbitrary hosts and
ports through this port." );
 script_set_attribute(attribute:"see_also", value:"http://www.winton.org.uk/zebedee/" );
 script_set_attribute(attribute:"solution", value:
"Make sure that use of this software agrees with your organization's
security policy." );
 script_set_attribute(attribute:"risk_factor", value:
"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/08");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 11965);

  exit(0);
}


include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(11965);
  if (!port) exit(0);
  if (silent_service(port)) exit(0); 
}
else port = 11965;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


comp_lvl = 6;
key_len = 128;
max_buf = 8196;
nonce = mkdword(rand()) + mkdword(rand());
protocol = mkbyte(2) + mkbyte(0);
redir_port = 80;
target = 0x00000000;
token = 0xffffffff;
udp_mode = 0;


# Exchange protocol version info.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

req =
  protocol +                                               # protocol 
  mkword(udp_mode) +                                       # flags
  mkword(max_buf) +                                        # max buffer size
  mkword(comp_lvl) +                                       # compression level (6 => zlib)
  mkword(redir_port) +                                     # redirection port
  mkword(key_len) +                                        # key length
  mkdword(token) +                                         # token (0xffffffff => new)
  nonce;                                                   # nonce
send(socket:soc, data:req);

res_1 = recv(socket:soc, length:2, min:2);
if (
  strlen(res_1) == 2 &&
  getbyte(blob:res_1, pos:0) >= 1 && getbyte(blob:res_1, pos:0) <= 2
)
{
  res_2 = recv(socket:soc, length:64, min:22);
  res = res_1 + res_2;

  # If...
  if (
    strlen(res) > 2 &&
    # udp mode must agree with what we specified and...
    getword(blob:res, pos:2) == udp_mode &&
    # the compression level is less than or equal to what we requested and...
    getword(blob:res, pos:6) <= comp_lvl &&
    # the key length is at least as long as what we requested and...
    getword(blob:res, pos:10) >= key_len &&
    # the port is either...
    (
      # what we specified or...
      getword(blob:res, pos:8) == redir_port || 
      # 0, meaning the connection failed
      getword(blob:res, pos:8) == 0
    )
  )
  {
    # Register and report the service.
    register_service(port:port, proto:"zebedee");

    security_note(port);
  }
}
close(soc);
