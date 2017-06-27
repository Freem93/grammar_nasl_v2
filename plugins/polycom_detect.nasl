#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34851);
 script_version("$Revision: 1.6 $");
 
 script_name(english: "Polycom Videoconferencing Unit Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is a Polycom videoconferencing unit." );
 script_set_attribute(attribute:"description", value:
"The remote web server provides an access to a Polycom
videoconferencing unit." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/11/21");
 script_cvs_date("$Date: 2011/03/14 21:48:11 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english: "Detect Polycom");
 
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports(80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function test(port)
{
  local_var page, server, r;

  server = get_http_banner(port: port, exit_on_fail: 1);
  if ("NetPort Software" >!< server && "Viavideo-Web" >!< server) return 0;

  page = http_get_cache(port: port, item: "/", exit_on_fail: 1);
  if ("Polycom" >< page || "polycom" >< page) return 1;
  r = http_send_recv3(method: "GET", item: "/u_indexmain.htm", port: port, exit_on_fail: 1);
  page = r[2];
  if ("Polycom" >< page || "polycom" >< page) return 1;
  return 0;
}
  
port = get_http_port(default: 80);

if (test(port: port))
{
 security_note(port: port);
 set_kb_item(name: 'www/'+port+'/polycom', value: TRUE);
}
