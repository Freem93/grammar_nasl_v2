#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15721);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2014/07/11 19:38:17 $");
 
 script_name(english:"PostNuke Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP-based content management system." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PostNuke, a content manager system written
in PHP.

Development of Postnuke stopped in 2008. Security flaws will not be 
patched." );

 script_set_attribute(attribute:"see_also", value:"http://www.postnuke.com/" );
 script_set_attribute(attribute:"see_also", value:"http://www.postnuke.com/module-Content-view-pid-6.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb447e90");
 script_set_attribute(attribute:"solution", value:
"Migrate to Zikula, which replaced PostNuke.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/13");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:postnuke_software_foundation:postnuke");
 script_end_attributes();

 
 summary["english"] = "Detects the presence of PostNuke";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl");
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

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

dirs = "";




function check(loc)
{
 local_var r, w, version, version_str;

 w = http_send_recv3(method:"GET", item:string(loc, "/index.php?module=Navigation"), port:port);
 if (isnull(w)) exit(0, "the web server did not answer");
 r = w[2];
 if('PostNuke' >< r && egrep(pattern:"<meta name=.generator. content=.PostNuke", string:r, icase:1) )
 {
	version_str = egrep(pattern:"<meta name=.generator. content=.PostNuke", string:r, icase:1);
	version_str = chomp(version_str);
 	version = ereg_replace(pattern:".*content=.PostNuke ([0-9.]*) .*", string:version_str, replace:"\1");
	if ( version == version_str ) version = "unknown";
	if ( loc == "" ) loc = "/";
	set_kb_item(name:"www/" + port + "/postnuke",
		    value:version + " under " + loc );
	set_kb_item(name:"www/postnuke", value: TRUE);
	
	dirs += "  - " + version + " under '" + loc + "'\n";
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
 if (dirs && !thorough_tests) break;
}

if ( dirs ) 
{
  info = string(
    "\n",
    "The following version(s) of PostNuke were detected :\n",
    "\n",
    dirs
  );
  security_hole(port:port, extra:info);
}

