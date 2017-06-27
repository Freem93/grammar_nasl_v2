#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16093);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2015/01/23 22:03:56 $");

 script_bugtraq_id(12133);
 script_osvdb_id(12606);

 script_name(english:"MySQL Eventum index.php email Parameter XSS");
 script_summary(english:"Test flaws in MySQL Eventum");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by a
cross-site scripting vulnerability.");
 script_set_attribute(attribute:"description", value:
"The MySQL Eventum install hosted on the remote web server is vulnerable
to a cross-site scripting attack because it fails to sanitize
user-supplied input to the 'email' parameter of the 'index.php' script
before using it to generate dynamic HTML output.

With a specially crafted URL, an attacker can use the remote server to
inject arbitrary HTML and script code into a user's browser to be
executed within the security context of the affected site.

Note that this install is also likely to be affected by several other
similar cross-site scripting vulnerabilities, although Nessus has not checked
for them.");
 script_set_attribute(attribute:"see_also", value:"http://www.cirt.net/MySQL+Eventum");
 script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=7552");
 script_set_attribute(attribute:"solution", value:"Upgrade to MySQL Eventum 1.4 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/03");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:eventum");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

 script_dependencie("mysql_eventum_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/eventum", "www/PHP");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'eventum', port:port, exit_on_fail:TRUE);
dir = install['dir'];

exploit = '<script>alert(16093)</script>';
vuln = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : "/index.php",
  qs       : 'err=3&email=">'+exploit,
  pass_re  : "<title>Login - Eventum</title>",
  pass_str : exploit
);
if (!vuln) exit(0, 'The MySQL Eventum install at '+build_url(qs:dir+'/', port:port)+ ' is not affected.');
