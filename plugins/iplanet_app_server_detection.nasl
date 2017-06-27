#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11402);
 script_version ("$Revision: 1.15 $");
 script_cvs_date("$Date: 2012/07/09 16:36:52 $");
 
 script_name(english:"Sun ONE (iPlanet) Application Server Detection");
 script_summary(english:"Sun ONE Application Server detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Sun ONE Application Server (formerly known
as iPlanet Application Server." ); 
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"see_also", value:"http://www.sun.com/software/products/appsrvr/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/16");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2012 Tenable Network Security, Inc.");

 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl", "DDI_Directory_Scanner.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);


#if(http_is_dead(port:port))exit(0);

dirs = get_kb_list(string("www/", port, "/content/directories"));
if(isnull(dirs)) dirs = make_list("/NASApp");
else dirs = make_list("/NASApp", dirs);


# First, we search for an iPlanet Application server.
foreach d (dirs)
{
  res = http_send_recv3(method:"GET", item:string(d, "/nessus/"), port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");
#
# Post-SP1 replies with a "200 OK" error code, followed by
# an error saying 'GX Error (GX2GX) (blah blah)'
#
if( (("ERROR: Unknown Type of Request" >< res[2])) ||
     ("GX Error (GX2GX)" >< res[2]))
 {
  set_kb_item(name:string("www/", port, "/SunOneApplicationServer/prefix"),
  	      value:d);
  report = string(
    "\n",
    "The Sun One Application Server uses the suffix :\n\n",
    d, "\n"
  );
  security_note(port:port, extra:report);	    
  exit(0);
 }
}

