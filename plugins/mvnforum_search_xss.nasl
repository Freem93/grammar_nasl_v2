#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#

# Fixed by Tenable:
#  - Improved description
#  - Adjusted XSS regex.


include("compat.inc");

if (description)
{
 script_id(18359);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2005-1183");
 script_bugtraq_id(13213);
 script_osvdb_id(16962);

 script_name(english:"mvnForum Search Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is susceptible to a
cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The version of mvnForum installed on the remote host is prone to a
cross-site scripting attack due to its failure to sanitize user-
supplied input to the search field." );
 script_set_attribute(attribute:"see_also", value:"http://www.mvnforum.com/mvnforum/viewthread?thread=3085" );
 script_set_attribute(attribute:"see_also", value:"http://www.mvnforum.com/mvnforum/viewthread?thread=2691" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to mvnForum version 1.0.0 RC4_04 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/19");
 script_cvs_date("$Date: 2015/01/14 03:46:11 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"MVNForum Search Cross-Site Scripting Vulnerability");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"Copyright (C) 2005-2015 Josh Zlatin-Amishav");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);

global_var	port;

function check(url)
{
 local_var req, res;

 req = http_get(item:url +"/search=%3Cscript%3Ealert('XSS')%3C/script%3E", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( res == NULL ) exit(0);
 if ( "matching entry in OnlineMember for '/search=<script>alert('XSS'" >< res )
 {
        security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(url:dir);
}
