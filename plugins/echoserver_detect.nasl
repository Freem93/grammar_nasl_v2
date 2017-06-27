#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34369);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2011/03/11 21:18:08 $");

  script_name(english:"echoServer Detection");
  script_summary(english:"Sends a MSG_PROXY_CONNECTED message");

 script_set_attribute(attribute:"synopsis", value:
"A tunneling service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running echoServer, which which allows peer-to-peer
or client-server applications to connect to one another as a series of
outbound connections, which may be helpful in avoiding problems caused
by firewalls and NAT'ing routers." );
 script_set_attribute(attribute:"see_also", value:"http://www.echogent.com/tech.htm" );
 script_set_attribute(attribute:"solution", value:
"Make sure that use of this software agrees with your organization's
security policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/09");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 1328);

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
  port = get_unknown_svc(1328);
  if (!port) exit(0);
  if (!silent_service(port)) exit(0); 
}
else port = 1328;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a MSG_PROXY_CONNECTED message and read the response.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

magic = 'EF1.0\x00';
type = 1;                                                  # type (1 => message)
msg = 2326;                                                # msg (2326 => MSG_PROXY_CONNECTED)
usertype = rand() % 0xffff;
datalen = 0;

req = 
  mkdword(msg) +
  mkdword(usertype) +
  mkdword(datalen);
req = 
  magic +
  mkbyte(type) +
  mkbyte(0) +                                              # padding
  mkword(strlen(req)+strlen(magic)+6) +
  mkword(0) +                                              # padding
  req;
req = mkdword(strlen(req)+4) + req;
send(socket:soc, data:req);

res_1 = recv(socket:soc, length:4, min:4);
if (strlen(res_1) == 4)
{
  len = getdword(blob:res_1, pos:0);
  if (len > 4 && len < 1024)
  {
    res_2 = recv(socket:soc, length:len-4);
    res = res_1 + res_2;

    # If...
    if (
      # The length agrees and...
      strlen(res) == len &&
      # it has the right magic and...
      stridx(res, magic) == 4 &&
      # it's a message and...
      getbyte(blob:res, pos:10) == type &&
      # the message length is correct
      getword(blob:res, pos:12) == (strlen(res)-4) &&
      # the message id agrees with what we sent
      getword(blob:res, pos:16) == msg
    )
    {
      # Register and report the service.
      register_service(port:port, proto:"echoserver");

      security_note(port);
    }
  }
}
close(soc);
