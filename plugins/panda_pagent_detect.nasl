#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25763);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2012/08/22 20:35:29 $");

  script_name(english:"Panda AdminSecure Communications Agent Detection");
  script_summary(english:"Starts a connection to pagent");

 script_set_attribute(attribute:"synopsis", value:
"A communications agent is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is a Communications Agent, which manages
communications between Panda AdminSecure and client computers for
centralized management of Panda antivirus software." );
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/25");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:pandasecurity:panda_antivirus");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 19226);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(19226);
  if (!port) exit(0);
}
else port = 19226;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);


# Start a connection.
req = "MESSAGE_FROM_REMOTE" + mkbyte(0);
req = mkdword(strlen(req)) + req;
send(socket:soc, data:req);
res = recv(socket:soc, length:4);
if (strlen(res) != 4) exit(0);


# If it looks like that worked...
if (raw_string(0x00, 0xe2, 0xab, 0x0c) == res)
{
  # Receive the next packet.
  res = recv(socket:soc, length:128);

  # If that looks like pagent...
  if (mkdword(6)+"200 OK" == res)
  {
    # Register and report the service.
    register_service(port:port, ipproto:"tcp", proto:"panda_pagent");
    security_note(port);
  }
}
close(soc);
