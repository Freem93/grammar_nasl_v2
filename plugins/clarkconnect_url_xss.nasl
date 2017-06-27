#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(43400);
  script_version("$Revision: 1.9 $");

  script_bugtraq_id(37446);
  script_xref(name:"OSVDB", value:"61265");

  script_name(english:"ClarkConnect proxy.php url Parameter XSS");
  script_summary(english:"Tries to inject script code through 'url' parameter");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is prone to a cross-
site scripting attack."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote web server is used by ClarkConnect, an Internet server and
gateway product, to process PHP scripts used for configuration.

The installed version includes a script, '/public/proxy.php', that
fails to sanitize user- supplied input to the 'url' parameter before
using it to generate dynamic HTML output. 

An attacker may be able to leverage this issue to inject arbitrary 
HTML and script code into a user's browser to be executed within the
security context of the affected site."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/508577/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Unknown at this time."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/12/21"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/12/23"
  );
 script_cvs_date("$Date: 2015/01/13 20:37:05 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 82);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:82);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP scripts.");


# Loop through directories and try to exploit the issue.
if (thorough_tests) dirs = list_uniq(make_list("/public", cgi_dirs()));
else dirs = make_list("/public");

alert = string("<script>alert('", SCRIPT_NAME, "')</script>");
vuln = test_cgi_xss(
  port     : port,
  cgi      : "/proxy.php",
  dirs     : dirs,
  qs       : "url="+urlencode(str:alert),
  pass_str : "<td><a href='"+alert+"'>"+alert+"</a></td",
  pass2_re : "title>system.clarkconnect.lan - Web Proxy Server"
);
if (!vuln) exit(0, "No vulnerable installs of ClarkConnect were discovered on the web server on port "+port+".");
