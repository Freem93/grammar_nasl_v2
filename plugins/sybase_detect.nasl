#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17161);
 script_version ("$Revision: 1.13 $");
 script_cvs_date("$Date: 2011/03/11 21:18:10 $");

 script_name(english:"Sybase TCP/IP Listener Service Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A database server is running on this port." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Sybase SQL server." );
 script_set_attribute(attribute:"solution", value:
"This port should not be reachable from non-authorized hosts.  Filter
incoming traffic to this host" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/21");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Sybase SQL TCP/IP listener is running");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencie("find_service1.nasl", "find_service2.nasl", "mssqlserver_detect.nasl");
 script_require_ports("Services/unknown", 5000);
 exit(0);
}

include('global_settings.inc');
include("misc_func.inc");
pkt = "0200020000000200000000000000000000000000000000000000000000000000000000000000004e65737375732d546573742d557365720000000000000000000000000000105858585858585858585858585858585858585858000000000000000000001430303030303061300000000000000000000000000000000000201881b82c080301060a090101000000000000000000737175656c646120312e30000000000000000000000000000000000000000b0000000000000000000000000000000000000000000000000000000000000000145858585858585858585858585858585858585858000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040200004d5344424c49420000000706000000000d110000000000000000000000000000000000000000000000000201004700000200000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030303000000003000000";

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
 port = get_kb_item("Services/unknown");
 if (! port) port = 5000;
}
else
 port = 5000;

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
send(socket:soc, data:hex2raw(s:pkt));
r = recv(socket:soc, length:1024);
if ( "Login failed" >< r )
	{
	register_service(proto:"sybase", port:port);
	security_note(port);
	}
