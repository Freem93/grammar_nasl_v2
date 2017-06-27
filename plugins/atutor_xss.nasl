#
# This script was written by Josh Zlatin-Amishav <josh at ramat doti cc>
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title (4/28/09)


include("compat.inc");

if(description)
{
 script_id(19587);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2005-2649");
 script_bugtraq_id(14598);
 script_osvdb_id(18842, 18843);

 script_name(english:"ATutor 1.5.1 Multiple Script XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to a
cross-site scripting issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ATutor, a CMS written in PHP. 

The remote version of this software is prone to cross-site scripting 
attacks due to its failure to sanitize user-supplied input." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Aug/259" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Aug/598" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/18");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:adaptive_technology_resource_centre:atutorv");
script_end_attributes();


 script_summary(english:"Checks for XSS in login.php");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"Copyright (C) 2005-2016 Josh Zlatin-Amishav");
 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("url_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);
if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);

# A simple alert.
xss = "<script>alert(" + SCRIPT_NAME + ")</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

foreach dir ( cgi_dirs() )
{
 req = http_get(
   item:string(
     dir, "/login.php?",
     'course=">', exss
   ), 
   port:port
 );
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

debug_print("res [", res, "].");

 if (
   egrep(string:res, pattern:"Web site engine's code is copyright .+ href=.http://www\.atutor\.ca") &&
   xss >< res
 )
 {
        	security_warning(port);
		set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        	exit(0);
 }
}
