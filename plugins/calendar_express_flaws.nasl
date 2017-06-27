#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19749);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2016/05/04 14:30:40 $");

 script_cve_id("CVE-2007-3627");
 script_bugtraq_id(14504, 14505);
 script_osvdb_id(18638, 38941, 38942, 38943);
 
 script_name(english:"Calendar Express Multiple Vulnerabilities (SQLi, XSS)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to
cross-site scripting and SQL injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Calendar Express, a PHP web calendar. 

Vulnerabilities exist in this version that could allow an attacker to
execute arbitrary HTML and script code in the context of the user's
browser, and SQL injection. 

An attacker could exploit these flaws to use the remote host to perform
attacks against third-party users, or to execute arbitrary SQL
statements on the remote SQL database." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/08");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Checks Calendar Express XSS and SQL flaws");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
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

if ( !get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

function check(loc)
{
 local_var r, req;
 req = http_get(item:string(loc, "/search.php?allwords=<br><script>foo</script>&cid=0&title=1&desc=1"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if ( "<script>foo</script>" >< r && egrep(string:r, pattern:"Calendar Express [0-9].+ \[Powered by Phplite\.com\]") )
 {
   	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
   exit(0);
 }
}

if (thorough_tests) dirs = list_uniq(make_list("/calendarexpress", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 check(loc:dir);
}
