#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31680);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2011/05/05 23:59:27 $");

  script_name(english:"solidDB Detection");
  script_summary(english:"Tries to log in with invalid credentials");

  script_set_attribute(attribute:"synopsis", value:
"A database service is listening on the remote host." );
  script_set_attribute(attribute:"description", value:
"The remote service is running solidDB, a relational database designed
for fast and always-on access." );
  script_set_attribute(attribute:"see_also", value:"http://www.solidtech.com/" );
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/28");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:soliddb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 1315);

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
  port = get_unknown_svc(2315);
  if (!port) exit(0);
  if (silent_service(port)) exit(0); 
}
else port = 2315;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Simulate a login.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

networkname = string("tcp ", get_host_name(), " ", port);
user = SCRIPT_NAME;
enc_pass = raw_string(0x8b, 0xb9, 0xd4, 0xf1, 0x3b, 0xc8, 0xc0, 0x11);
me = string("nessus (", this_host(), ")");

req = 
  raw_string(0x02, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00) +
  mkdword(1) +
  mkdword(strlen(networkname)) + networkname +
  mkdword(strlen(user)) + user +
  mkdword(strlen(enc_pass)) + enc_pass + 
  mkdword(4) +
  mkdword(3) +
  mkdword(2) +
  mkdword(1) +
  mkdword(1) +
  mkdword(0) +
  mkdword(0x14) +
  mkbyte(4) +
  mkword(strlen(me)) + me;
send(socket:soc, data:req);
res = recv(socket:soc, length:64, min:16);
close(soc);


# If...
if (
  # it's long enough and...
  strlen(res) >= 0x1b &&
  # the start of the packet looks right
  substr(res, 0, 6) == raw_string(0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00) &&
  getdword(blob:res, pos:7) == 1
)
{
  # Register / report the service.
  register_service(port:port, proto:"soliddb");
  security_note(port);
}
