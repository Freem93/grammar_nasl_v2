#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25445);
 script_version("$Revision: 1.6 $");
 script_cvs_date("$Date: 2012/08/02 18:41:22 $");
 
 script_name(english:"Symantec Web Security Detection");
 script_summary(english:"Checks for SWS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service filters HTTP / FTP content." );
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be running Symantec Web Security, 
for filtering traffic of viruses and inappropriate content." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/07");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:web_security");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("httpver.nasl");
 script_require_ports("Services/www", 8002);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/www");
if ( ! port ) port = 8002;

if(get_port_state(port))
{
  banner = get_http_banner(port:port);
  if (
    banner && 
    "Server: SWS-" >< banner
  ) {
    ver = strstr(banner, "Server: SWS-") - "Server: SWS-";
    if (ver) ver = ver - strstr(ver, '\r');
    if (ver) ver = ver - strstr(ver, '\n');
    if (ver && ver =~ "^[0-9]") {
      security_note(port);
      set_kb_item(name:string("www/", port, "/SWS"),value:string(ver));
    }
  }
}
