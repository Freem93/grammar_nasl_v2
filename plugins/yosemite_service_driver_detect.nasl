#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34756);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2011/03/11 21:18:10 $");

  script_name(english:"Yosemite Backup Service Driver Detection");
  script_summary(english:"Simulates a connection from Yosemite Backup Administrator");

 script_set_attribute(attribute:"synopsis", value:
"A database service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Yosemite Backup, a commercial backup
solution for Windows, Linux, and Novell NetWare and targetting
small-to-medium sized businesses." );
 script_set_attribute(attribute:"see_also", value:"http://www.barracudaware.com/products/server-backup/products" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/11/12");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 3817);

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
  port = get_unknown_svc(3817);
  if (!port) exit(0);
  if (!silent_service(port)) exit(0); 
}
else port = 3817;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


cmd = "Sup: Registration";
name = "NESSUS";
magic = rand();


# Simulate a connection from Yosemite Backup Administrator.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

if (strlen(cmd) < 31) cmd += crap(data:mkbyte(0), length:31-strlen(cmd));
if (strlen(name) < 31) name += crap(data:mkbyte(0), length:31-strlen(name));

octs = split(this_host(), sep:'.', keep:FALSE);
ip_nessus = mkbyte(int(octs[0])) + mkbyte(int(octs[1])) + mkbyte(int(octs[2])) + mkbyte(int(octs[3]));

req = mkdword(0x8454) +
  mkdword(0) +
  mkdword(6) +
  mkdword(0x92) +
  mkdword(0) + mkdword(0) + mkdword(magic) + mkdword(0) +
  mkdword(1) + ip_nessus +
  crap(data:mkbyte(0), length:28) +
  mkdword(1) + mkdword(port) +
  crap(data:mkbyte(0), length:8) +
  name + 
  cmd;
send(socket:soc, data:req);
res = recv(socket:soc, length:1024, min:128);
close(soc);


# If ...
if (
  # the packet length is correct and ...
  strlen(res) > 16 && strlen(res) == getdword(blob:res, pos:12) &&
  # the packet looks like a response and ...
  0x8453 == getdword(blob:res, pos:0) &&
  cmd >< res &&
  # our magic appears in the correct spot
  magic == getdword(blob:res, pos:0x18)
)
{
  # Register and report the service.
  register_service(port:port, proto:"yosemite_backup");

  security_note(port);
}
