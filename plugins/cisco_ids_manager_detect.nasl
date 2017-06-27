#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11689);
 script_version ("$Revision: 1.15 $");
 script_cvs_date("$Date: 2013/07/01 21:36:51 $");
 
 script_name(english:"Cisco IDS Device Manager Detection");
 script_summary(english:"Cisco IDS Management Web Server Detectiion");

 script_set_attribute(
   attribute:"synopsis",
   value:"An intrusion detection system manager is running on the remote host."
 );
 script_set_attribute(
   attribute:"description", 
   value:"This host is running the Cisco IDS device manager."
 );
 script_set_attribute(
   attribute:"solution", 
   value:"n/a"
 );
 script_set_attribute(
   attribute:"risk_factor", 
   value:"None"
 );
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/03");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:ids_device_manager");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CISCO");

 script_copyright(english:"This script is Copyright (C) 2002-2013 Tenable Network Security, Inc.");

 script_dependencie("httpver.nasl", "broken_web_server.nasl");
 script_require_ports("Services/www", 443);

 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:443, dont_break: 1);
res = http_get_cache(port:port, item:"/", exit_on_fail: 1);

if ("<title>Cisco Systems IDS Device Manager</title>" >< res )
{
  security_note(port);
  set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
}
