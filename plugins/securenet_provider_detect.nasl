#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18533);
 script_version("$Revision: 1.8 $");
 script_cvs_date("$Date: 2011/11/28 21:39:46 $");
 
 script_name(english:"Intrusion.com SecureNet Provider Detection");

 script_set_attribute(attribute:"synopsis", value:
"A intrusion detection system is installed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to run the Intrusion.com SecureNet provider on this port." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/20");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for Intrusion.com SecureNet provider console");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("httpver.nasl");
 script_require_ports(80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = 80;
if(get_port_state(port))
{
 rep = http_get_cache(item:"/", port:port);
 if( rep == NULL ) exit(0);
 if(" - SecureNet Provider WBI</title>" >< rep)
 {
   security_note(port);
   set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
 }
}
