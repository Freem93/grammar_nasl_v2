#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26195);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2011/03/11 21:18:09 $");

  script_name(english:"OEJP Daemon Detection");
  script_summary(english:"Sends a protocol version string");

 script_set_attribute(attribute:"synopsis", value:
"There is an OEJP daemon is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running an OEJP (OpenEJB Enterprise Javabean
Protocol) daemon, a fast and lightweight EJB server." );
 script_set_attribute(attribute:"see_also", value:"http://openejb.apache.org/" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/28");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 4201);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
  port = get_unknown_svc(4201);
  if (!port) exit(0);
}
else port = 4201;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a version string (ProtocolMetaData).
req = "OEJP/1.0";
send(socket:soc, data:req);
res = recv(socket:soc, length:64, min:8);
close(soc);


# If...
if (
  # the response is long-enough and...
  strlen(res) == 8 &&
  # it looks right
  "OEJP/" >< res && res =~ "^OEJP/[0-9]\.[0-9]$"
)
{
  # Register and report the service.
  register_service(port:port, proto:"oejp");
  security_note(port);
}
