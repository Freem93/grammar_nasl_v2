#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25761);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2012/07/20 18:51:35 $");

  script_name(english:"Ipswitch Instant Messaging Server Detection");
  script_summary(english:"Tries to log in to IMServer");

 script_set_attribute(attribute:"synopsis", value:
"An instant messaging server is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is an Ipswitch IM Server, the server portion of
Ipswitch Instant Messaging, a secure, instant messaging product
targeted at businesses and running on Windows." );
 script_set_attribute(attribute:"see_also", value:"http://www.ipswitch.com/products/instant_messaging/index.asp" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/25");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:ipswitch:imserver");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 5177);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(5177);
  if (!port) exit(0);
}
else port = 5177;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


set_byte_order(BYTE_ORDER_BIG_ENDIAN);


# Simulate a login.
req1 = mkdword(0x07) + mkdword(0x01);
req2 = raw_string(
  0x80, 0xd5, 0x20, 0x4a, 0xef, 0x0d, 0x0a, 0xc0, 
  0xd9, 0x9f, 0x1e, 0x07, 0x4e, 0x81, 0xb4, 0xcf, 
  0x87, 0xc4, 0x1a, 0x75, 0x7c, 0x94, 0x1c, 0xb8, 
  0x84, 0x3d, 0x5d, 0xb6, 0xb6, 0xa8, 0xc7, 0xb9, 
  0xdd, 0x44, 0x1d, 0xcc, 0x59, 0x25, 0x9c, 0x2e, 
  0x47, 0xf7, 0xed, 0xcd, 0x47, 0x61, 0x72, 0x45, 
  0x0c, 0xd4, 0x77, 0x01, 0x8f, 0xf9, 0x91, 0xe8, 
  0x16, 0xeb, 0x19, 0xb1, 0x35, 0x37, 0x04, 0xe1, 
  0xf5, 0xf3, 0x15, 0x89, 0xf6, 0xbb, 0x8e, 0x4f, 
  0x99, 0x5d, 0x51, 0x2c, 0x4e, 0x3a, 0x0a, 0x3f, 
  0x67, 0x8e, 0x2b, 0x10, 0x4b, 0x09, 0xf1, 0xbb, 
  0x53, 0x76, 0xdd, 0x0f, 0xf1, 0x97, 0x39, 0xc0
);
send(socket:soc, data:req1+req2);
res1 = recv(socket:soc, length:8);


# If...
if (
  # we got 8 characters and...
  strlen(res1) == 8 &&
  # the response equals our first packet
  res1 == req1
)
{
  # Receive the next packet.
  res2 = recv(socket:soc, length:128);
  subres2 = substr(res2, 0, 7);
  
  # If that looks like...
  if (
    # an unsuccessful login response or...
    subres2 == raw_string(0x88, 0x50, 0xb7, 0x26, 0xc4, 0x8f, 0x4f, 0x09) ||
    # a successful login response
    subres2 == raw_string(0xd9, 0x9f, 0x1e, 0x07, 0x4e, 0x81, 0xb4, 0xcf)
  )
  {
    # Register and report the service.
    register_service(port:port, ipproto:"tcp", proto:"ipswitch_imserver");
    security_note(port);
  }
}
close(soc);
