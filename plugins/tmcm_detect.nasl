#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18178);
 script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2015/10/21 20:34:21 $");
 
 script_name(english:"Trend Micro TMCM Console Management Detection");
 script_summary(english:"Checks for Trend Micro TMCM console management");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web management console is leaking information."
 );
 script_set_attribute(
   attribute:"description",
   value:
"The remote host appears to run Trend Micro Control Manager.  It is
accepting connections to the web console management interface, which
may reveal sensitive information.  A remote attacker could use this
information to mount further attacks."
 );
 script_set_attribute(
   attribute:"solution",
   value:"Filter incoming traffic to this port."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/02");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("httpver.nasl", "broken_web_server.nasl");
 script_require_ports(80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (port != 80 ) exit(0, "This web server runs only on port 80, not "+port+".");

if (! get_port_state(port)) exit(0, "Port "+port+" is closed.");

 req = http_get(item:"/ControlManager/default.htm", port:port);
 rep = http_keepalive_send_recv(port:port, data:req);
 if( rep == NULL ) exit(0);

#<title>
#Trend Micro Control Manager 3.0
#</title>

 if (egrep(pattern:"Trend Micro Control Manager.+</title>", string:rep, icase:1))
 {
	set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
	security_warning(port);
 }
