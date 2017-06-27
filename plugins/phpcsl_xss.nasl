#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14368);
 script_version("$Revision: 1.19 $");
 script_cve_id("CVE-2004-1746");
 script_bugtraq_id(11038);
 script_osvdb_id(9168);
 
 script_name(english:"PHP Code Snippet Library index.php Multiple Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script affected by a cross-site
scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHP Code Snippet Library (PHP-CSL), a
library written in PHP. 

The remote version of this software fails to sanitize input to the
'cat_select' parameter of the 'index.php' script.  This can be used to
take advantage of the trust between a client and server allowing the
malicious user to execute malicious JavaScript on the client's
machine." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Aug/338" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP-CSL version 0.9.1 or later as that is rumored to
address the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/24");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:php_code_snippet_library:php_code_snippet_library");
 script_end_attributes();

 
 script_summary(english:"Checks for the presence of an XSS bug in PHP-CSL");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
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

global_var	port;

port = get_http_port(default:80, php: 1, no_xss: 1);

function check(loc)
{
 local_var r, w;

 w = http_send_recv3(method:"GET", item:string(loc, "/index.php?cat_select=<script>foo</script>"), port:port, exit_on_fail: 1);
 r = w[2];
 
 if('<script>foo</script>' >< r && "PHP-CSL" >< r)
 {
 	security_warning(port:port, extra:'\nThe following URL is vulnerable :\n' + loc + "/index.php?cat_select=<script>foo</script>");
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}
