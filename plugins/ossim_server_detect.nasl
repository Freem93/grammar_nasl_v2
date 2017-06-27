#
# Script Written By Ferdy Riphagen 
# Script distributed under the GNU GPLv2 License. 
#



include("compat.inc");

if (description) {
 script_id(28292);
 script_version("$Revision: 1.5 $");
 script_cvs_date("$Date: 2011/03/11 21:18:09 $");

 name["english"] = "OSSIM Server Detection";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"An ossim-server daemon is listening on the remote port." );
 script_set_attribute(attribute:"description", value:
"The remote system is running an ossim-server daemon. OSSIM (Open Source
Security Information Management) is a centralized security management 
information system, and the ossim-server provides centralized access to the
backend database and framework." );
 script_set_attribute(attribute:"see_also", value:"http://www.ossim.net/" );
 script_set_attribute(attribute:"solution", value:
"If possible, filter incoming connections to the service so that it is
used by trusted sources only." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/11/26");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 summary["english"] = "Checks for an OSSIM server";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 script_copyright(english:"This script is Copyright (C) 2007-2011 Ferdy Riphagen");

 script_dependencies("find_service1.nasl");
 script_require_ports("Services/unknown", 40001);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  ) {
  port = get_unknown_svc(40001);
  if (!port) exit(0);
}
else port = 40001;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (soc) { 
	rand = rand() % 10;
	data = 'connect id="' + rand + '" type="sensor"\n'; 
	send(socket:soc, data:data);
	recv = recv(socket:soc, length:64, min:10);

	if (strlen(recv) && recv == 'ok id="' + rand + '"\n') {
		security_note(port:port);
		register_service(port:port, ipproto:"tcp", proto:"ossim_server");
	}
	close(soc);
}
