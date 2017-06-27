#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10675);
 script_version ("$Revision: 1.18 $");
 script_osvdb_id(559);
 script_cvs_date("$Date: 2014/05/09 18:59:10 $");
 script_name(english:"Check Point FireWall-1 Telnet Client Authentication Detection");

 script_set_attribute(attribute:"synopsis", value:
"A Check Point FireWall-1 Client Authentication server is listening on
this port." );
 script_set_attribute(attribute:"description", value:
"The Check Point FireWall-1 Client Authentication server is used to
authenticate a user via telnet.  Once authenticated, the user can get
more privileges on the network (ie, get access to hosts that were
previously blocked by the firewall)." );
 script_set_attribute(attribute:"solution", value:
"If you do not use this feature, disable it." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/05/26");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Connects to FW1 Client Authentication Server");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Firewalls");
 script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
 script_require_ports(259);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if ( ! get_port_state(259) ) exit(0);

soc = open_sock_tcp(259);
if ( ! soc ) exit(0);

r = recv_line(socket:soc, length:4096);
if ( "Check Point FireWall-1 Client Authentication Server running on " >< r )
{
 register_service(port:259, proto:"cp-client-auth-svr");
 report = '\nThe banner of the remote service is :\n\n' + r;
 security_note(port:259, extra:report);
}
 
