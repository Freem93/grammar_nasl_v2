#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(17282);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2014/06/20 20:41:22 $");

 script_name(english:"vBulletin Detection");
 script_summary(english:"Checks for the presence of vBulletin");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a bulletin board system written in PHP." );
 script_set_attribute(attribute:"description", value:
"The remote host is running vBulletin, a commercial web-based message
forum application written in PHP." );
 script_set_attribute(attribute:"see_also", value:"http://www.vbulletin.com/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/07");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:vbulletin:vbulletin");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if(!can_host_php(port:port)) exit(0);


foreach d (list_uniq(make_list("/forum", cgi_dirs())))
{
 req = http_get(item:string(d, "/index.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 res = egrep(pattern:" content=.vBulletin ", string:res, icase:TRUE);
 if( res )
 {
  if (d == "") d = "/";
  vers = ereg_replace(pattern:".*vBulletin ([0-9.]+).*", string:res, replace:"\1", icase:TRUE);
  set_kb_item(name:string("www/", port, "/vBulletin"),
  	      value:string(vers," under ",d));
  set_kb_item(name:"www/vBulletin", value:TRUE);

  if (report_verbosity)
  {
    report = string(
      "\n",
      "The remote host is running vBulletin " + vers + " under " + d, "\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);     
 }
} 
