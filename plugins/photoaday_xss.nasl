#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14357);
 script_version("$Revision: 1.20 $");
 script_bugtraq_id(11009);
 script_xref(name:"OSVDB", value:"9161");
 
 script_name(english:"PHP-Nuke PhotoADay Module pad_selected Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an PHP application that is affected by 
a cross-site scripting vulnerability." );

 script_set_attribute(attribute:"description", value:
"The remote host is running PhotoADay, a web-based photo 
album management software. The installed version fails 
to sanitize input passed to the 'pad_selected' parameter
before using it to generate dynamic content. An unauthenticated, 
remote attacker may be able to leverage this issue to 
inject arbitrary HTML or script code into a user's 
browser to be executed within the security context of 
the affected site." );

 script_set_attribute(attribute:"see_also", value:"http://www.securitytracker.com/alerts/2004/Aug/1011027.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/21");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();
 
 script_summary(english:"Checks for the presence of an XSS bug in PhotoAday");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses : XSS");
 script_dependencie("cross_site_scripting.nasl", "http_version.nasl");
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
if(!can_host_php(port:port))
  exit(1,"The remote web server on port "+port+" does not support PHP.");
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(1,"generic_xss KB already set.");

test_cgi_xss(port: port, dirs: cgi_dirs(), cgi: "/modules.php", 
 qs: "name=Photo_A_Day&action=single&pad_selected=44<script>foo</script>", 
 pass_str: '<script>foo</script>');
