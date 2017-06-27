#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(24004);
  script_version ("$Revision: 1.10 $");
  script_name(english: "WebDAV Directory Enumeration");
 script_set_attribute(attribute:"synopsis", value:
"Several directories on the remote host are DAV-enabled." );
 script_set_attribute(attribute:"description", value:
"WebDAV is an industry standard extension to the HTTP specification.
It adds a capability for authorized users to remotely add and manage
the content of a web server.

If you do not use this extension, you should disable it." );
 script_set_attribute(attribute:"solution", value:
"Disable DAV support if you do not use it." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/11");
 script_cvs_date("$Date: 2011/03/14 21:48:15 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english: "Determines which directories are DAV enabled");
  script_category(ACT_GATHER_INFO);
  script_copyright(english: "This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
  script_family(english: "Web Servers");
  script_dependencie("webmirror.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

dirs = get_kb_list(string("www/", port, "/content/directories"));
if ( isnull(dirs) ) exit(0);
dirs = make_list(dirs);

list = NULL;
failure = 0;

foreach dir ( dirs )
{ 
 if ( dir[0] == '/' )
 {
 if ( strlen(dir) > 0 && dir[strlen(dir) - 1] != '/' )
	dir += '/';
 r = http_send_recv3(port: port, item: dir, method: 'OPTIONS');
 if (isnull(r)) break;
 if (egrep(pattern:"^DAV:", string: r[1], icase: 1))
  {
   list += ' - ' + dir + '\n';
   set_kb_item(name:"www/" + port + "/webdav/directories", value:dir);
  }
  else failure ++;
 }
}

#
# Do not display a message if every dir has webdav enabled, as it will
# show up in webdav_detect.nasl
# 
if ( failure && strlen(list) )
{
  report = 'The following directories are DAV enabled :\n' + list; 
  security_note(port:port, extra:report);
}
