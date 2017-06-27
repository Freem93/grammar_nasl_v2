#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18219);
 script_version("$Revision: 1.9 $");
 script_cvs_date("$Date: 2012/05/10 22:10:39 $");
 
 script_name(english:"Clearswift MIMEsweeper Manager Console Detection");
 script_summary(english:"Checks for MIMEsweeper manager console");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web and email gateway security 
application.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running MIMEsweeper for SMTP, 
connections are allowed to the web MIMEsweeper manager console.

Letting attackers know that you are using this software will help them 
to focus their attack or will make them change their strategy.");
 script_set_attribute(attribute:"see_also", value:"http://www.clearswift.com/");
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/10");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
 script_family(english:"Misc.");

 script_dependencie("httpver.nasl", "broken_web_server.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

#da code now

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (! get_port_state(port)) exit(0, "Port "+port+" is closed.");

 req = http_get(item:"/MSWSMTP/Common/Authentication/Logon.aspx", port:port);
 rep = http_keepalive_send_recv(port:port, data:req);
 if( rep == NULL ) exit(1, "The web server on port "+port+" failed to respond.");

 if ("<title>MIMEsweeper Manager</title>" >< rep)
 {
	security_note(port);
	set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
 }

