#
# This script was written by Josh Zlatin-Amishav <josh at ramat dot cc>
#
# This script is released under the GNU GPLv2

include("compat.inc");

if (description)
{
 script_id(19500);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2015/01/13 20:37:05 $");

 script_bugtraq_id(14396);
 script_osvdb_id(
  18306,
  18307,
  18308,
  18309,
  18310,
  18311,
  18312,
  18313,
  18314
 );

 script_name(english:"BMForum Multiple Script XSS");
 script_summary(english:"Checks for XSS in topic.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is vulnerable to
cross-site scripting attacks.");
 script_set_attribute(attribute:"description", value:
"The remote host is running BMForum, a web forum written in PHP.

The remote version of this software is affected by several cross-site
scripting vulnerabilities. The issues are due to failures of the
application to properly sanitize user-supplied input.");
 # http://lostmon.blogspot.com/2005/07/multiple-cross-site-scripting-in.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?719f1faa");
 script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/27");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/24");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:bmforum:bmforum");
 script_end_attributes();

 script_category(ACT_ATTACK);

 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"Copyright (C) 2005-2015 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport", "www/PHP");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);
if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);

# A simple alert.
xss = '"><script>alert(" + SCRIPT_NAME + ")</script>';
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

foreach dir ( cgi_dirs() )
{
 req = http_get(
   item:string(
     dir, "/topic.php?filename=1",
     exss
   ),
   port:port
 );


 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if (isnull(res)) exit(0);

 if ( xss >< res )
 {
        security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
 }
}
