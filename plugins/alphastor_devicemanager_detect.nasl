#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(33283);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2011/03/11 21:18:07 $");

  script_name(english:"EMC AlphaStor Device Manager Detection");
  script_summary(english:"Detects an AlphaStor Device Manager rrobotd service");

 script_set_attribute(attribute:"synopsis", value:
"There is a device backup manager installed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a EMC AlphaStor Device Manager service.
AlphaStor is a tape backup management and library sharing for EMC
NetWorker." );
 script_set_attribute(attribute:"see_also", value:"http://www.emc.com/products/detail/software/alphastor.htm" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/01");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 3000);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");


function mk_command(cmd, s)
{
 local_var len;

 len = strlen(s);

 return mkbyte(cmd + 0x41) + s + crap(data:mkbyte(0), length:0x200-len) + mkbyte(0);
}


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  ) {
  port = get_unknown_svc(3000);
  if ( ! port ) exit(0);
}
else port = 3000;
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


req = mk_command(cmd:0x27, s:"nessus");
send(socket:soc, data:req);

res = recv(socket:soc, length:1024);
close(soc);

if ("rrobotd:rrobotd" >!< res)
  exit(0);

register_service(port:port, ipproto:"tcp", proto:"alphastor-devicemanager");

security_note(port:port);

