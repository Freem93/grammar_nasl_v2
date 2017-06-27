#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#


include("compat.inc");

if(description)
{
 script_id(18255);
 script_version ("$Revision: 1.18 $");

 script_cve_id("CVE-2005-1593", "CVE-2005-1594", "CVE-2005-1595");
 script_bugtraq_id(13560);
 script_osvdb_id(16155, 16156, 16157);

 script_name(english:"CodeThatShoppingCart Multiple Remote Vulnerabilities (SQLi, XSS, ID)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the CodeThat.com ShoppingCart, a shopping
cart program written in PHP. 

The remote version of this software fails to sanitize input to the
'id' parameter of the 'catalog.php' script before using it in a
database query.  An unauthenticated, remote attacker could leverage
this issue to launch SQL injection as well as cross-site scripting
attacks against the affected software and associated database 
application." );
 script_set_attribute(attribute:"see_also", value:"http://lostmon.blogspot.com/2005/05/codethat-shoppingcart-critical.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/09");
 script_cvs_date("$Date: 2015/02/02 19:32:50 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 summary["english"] = "Checks for a SQL injection in CodeThatShoppingCart";

 script_summary(english:summary["english"]);

 script_family(english:"CGI abuses");
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"Copyright (C) 2005-2015 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

global_var port;

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

function check(url)
{
 local_var req, res;

 req = http_get(item:url +"/catalog.php?action=category_show&id='", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( "select id from products P, category_products CP where P.id=CP.product_id and CP.category_id=" >< res )
 {
        security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
        exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
  check(url:dir);
}


