#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15722);
 script_version("$Revision: 1.10 $");
 
 name["english"] = "CVSTrac Detection";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web-based source code management
application." );
 script_set_attribute(attribute:"description", value:
"The remote host is running CVSTrac, a web-based bug and patch-set
tracking system for CVS." );
 script_set_attribute(attribute:"see_also", value:"http://www.cvstrac.org/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/13");
 script_cvs_date("$Date: 2011/03/14 21:48:02 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Detects the presence of CVSTrac");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if(!can_host_php(port:port))exit(0);

dirs = "";


function check(loc)
{
 local_var line, w, version, version_str;

 w = http_send_recv3(method:"GET", item:string(loc, "/index"), port:port);
 if (isnull(w)) exit(0);
 line = egrep(pattern:"<a href=.about.>CVSTrac version .*", string: w[2]);
 if ( line ) 
 {
	version_str = chomp(line);
 	version = ereg_replace(pattern:"<a href=.about.>CVSTrac version ([0-9.]*)</a>", string:version_str, replace:"\1");
	if ( version == version_str ) version = "unknown";
	if ( loc == "" ) loc = "/";
	set_kb_item(name:"www/" + port + "/cvstrac",
		    value:version + " under " + loc );
	
	dirs += " - " + loc + '\n';
 }
}

# Loop through directories.
if (thorough_tests) check_dirs = list_uniq(make_list("/cvstrac", cgi_dirs()));
else check_dirs = make_list(cgi_dirs());

foreach dir (check_dirs)
{
 check(loc:dir);
}

if ( dirs ) 
{
  info = string(
    "\n",
    "CVSTrac is installed under the following location(s) :\n",
    "\n",
    dirs
  );
  security_note(port:port, extra:info);
}
