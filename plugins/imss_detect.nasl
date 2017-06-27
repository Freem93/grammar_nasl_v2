#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(17244);
 script_version("$Revision: 1.10 $");
 
 script_name(english:"Trend Micro IMSS Console Management Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote hsot apepars to be running a Security Suite with a web
interface." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to run Trend Micro Interscan Messaging 
Security  Suite, connections are allowed to the web console 
management.

Make sure that only authorized hosts can connect to this service, as
the information of its existence may help an attacker to make more 
sophisticated attacks against the remote network." );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/01");
 script_cvs_date("$Date: 2011/11/28 21:39:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for Trend Micro IMSS web console management");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("httpver.nasl", "broken_web_server.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0, "Port "+port+" is closed.");

  req = http_get(item:"/commoncgi/servlet/CCGIServlet?ApHost=PDT_InterScan_NT&CGIAlias=PDT_InterScan_NT&File=logout.htm", port:port);
 
 rep = http_keepalive_send_recv(port:port, data:req);
 if (isnull(rep)) exit(1, "The web server on port "+port+" failed to respond.");
 if("<title>InterScan Messaging Security Suite for SMTP</title>" >< rep)
 {
   security_note(port);
   set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
 }
