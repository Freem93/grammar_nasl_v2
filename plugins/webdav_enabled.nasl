#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(11424);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2011/03/14 21:48:15 $");

  script_name(english: "WebDAV Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is running with WebDAV enabled." );
 script_set_attribute(attribute:"description", value:
"WebDAV is an industry standard extension to the HTTP specification.
It adds a capability for authorized users to remotely add and manage
the content of a web server.

If you do not use this extension, you should disable it." );
 script_set_attribute(attribute:"solution", value:
"http://support.microsoft.com/default.aspx?kbid=241520" );
 script_set_attribute(attribute:"risk_factor", value:"None" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/20");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Checks the presence of WebDAV");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

r = http_send_recv3(port: port, item: '*', method: 'OPTIONS');
if(egrep(pattern:"^DAV:", string: r[1], icase: 1) || 
     egrep(pattern:"^Server: Apache.* DAV/", string:r[1]) )
   {
    security_note(port);
    set_kb_item(name: "www/"+port+"/webdav", value: TRUE);
   }
