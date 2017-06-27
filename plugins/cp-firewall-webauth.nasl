#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10676);
 script_version ("$Revision: 1.19 $");
 script_name(english:"Check Point FireWall-1 HTTP Client Authentication Detection");
 script_set_attribute(attribute:"synopsis", value:
"A Check Point FireWall-1 Client Authentication web server is listening on 
this port." );
 script_set_attribute(attribute:"description", value:
"The Check Point FireWall-1 Client Authentication web server is used to 
authenticate a user via HTTP. Once authenticated, the user can get more 
privileges on the network (ie: get access to hosts which were previously 
blocked by the firewall)." );
 script_set_attribute(attribute:"solution", value:
"If you do not use this feature, disable it." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/05/26");
 script_cvs_date("$Date: 2011/03/15 18:34:10 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Connects to FW1 Client Authentication Server");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Firewalls");
 script_copyright(english:"This script is Copyright (C) 2001-2011 Tenable Network Security, Inc.");
 script_dependencies("http_version.nasl");
 script_require_ports(900);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = 900;
if (! get_port_state(port) ) exit(0);

res = http_get_cache(item:"/", port:port, exit_on_fail: 1);

if ('<INPUT TYPE="hidden" NAME="STATE" VALUE="1">' >< res  && 'FireWall-1 message: ' >< res )
	{
		security_note(port);
 		register_service(port:port, proto:"cp-client-auth-web-svr");
	}
