#
# This script was written by Frank Berger <dev.null@fm-berger.de>
# <http://www.fm-berger.de>
#
# This vulnerability was found by 
# Rafel Ivgi, The-Insider <theinsider@012.net.il>
#
# License: GPL v 2.0  http://www.gnu.org/copyleft/gpl.html
#
#


include("compat.inc");

if(description)
{
 script_id(12112);
 script_version("$Revision: 1.22 $");
 name["english"] = "Oracle 9iAS iSQLplus XSS";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The login-page of Oracle9i iSQLplus allows the injection of HTML and
JavaScript code via the username and password parameters." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Oracle9i 'isqlplus' CGI
that is vulnerable to a cross-site scripting attack. 

An attacker may exploit this flaw to steal the cookies of legitimate
users on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securitytracker.com/alerts/2004/Jan/1008838.html" );
 script_set_attribute(attribute:"solution", value: "No solution is known.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/03/17");
 script_cvs_date("$Date: 2016/12/07 20:46:55 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_server");
 script_end_attributes();

 
 script_summary(english:"Test for the possibility of an Cross-Site Scripting XSS Attack in Oracle9i iSQLplus");
 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Frank Berger");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("find_service1.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(get_port_state(port))
{ 
 req = http_get(item:"/isqlplus?action=logon&username=foo%22<script>foo</script>&password=test", port:port);	      
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( res == NULL ) exit(0);
 if( '<script>foo</script>' >< res )	
 {
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
 }
}
