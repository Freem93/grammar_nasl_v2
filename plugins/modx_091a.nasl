#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21235);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/02/11 21:07:49 $");

  script_cve_id("CVE-2006-1820", "CVE-2006-1821");
  script_bugtraq_id(17532, 17533);
  script_osvdb_id(24697, 24698);

  script_name(english:"MODx < 0.9.1a Multiple Vulnerabilities");
  script_summary(english:"Tries to exploit a XSS flaw in MODx");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MODx, a content management system written
in PHP.

The version of MODx installed on the remote host fails to sanitize
input to the 'id' parameter of the 'index.php' script before using it
to generate dynamic HTML output.  An unauthenticated attacker can
exploit this to inject arbitrary script and HTML into a user's
browser.

Also, the same lack of input sanitation reportedly can be leveraged to
launch directory traversal attacks against the affected application,
although exploitation may only be successful if the affected host is
running Windows and if PHP's 'magic_quotes_gpc' setting is disabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/431010/30/0/threaded");
 script_set_attribute(attribute:"see_also", value:"http://modxcms.com/forums/index.php/topic,3982.0.html" );
 script_set_attribute(attribute:"solution", value:"Upgrade to MODx version 0.9.1a or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/17");

script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:modxcms:modxcms");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("modx_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/modx");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);

if (get_kb_item("www/"+port+"/generic_xss")) exit(1, "The web server itself is prone to XSS attacks.");

install = get_install_from_kb(appname:'modx', port:port, exit_on_fail:TRUE);
# A simple alert.
xss = string("<script>alert(", SCRIPT_NAME, ")</script>");
dirs = make_list(install['dir']);

foreach dir (dirs)
{
  # Try to exploit the issue.
  res = http_send_recv3(method:"GET",item: dir+'/index.php?id=2'+urlencode(str:xss), port:port, exit_on_fail:TRUE);

  # There's a problem if we see our XSS.
  if (string("WHERE (sc.id=2", xss, " )") >< res[2])
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
