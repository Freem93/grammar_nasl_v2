#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50651);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2010-4637");
  script_bugtraq_id(44704);
  script_osvdb_id(69071);

  script_name(english:"FeedList Plugin for WordPress 'i' Parameter XSS");
  script_summary(english:"Attempts to inject script code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a cross-
site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the FeedList plugin for WordPress installed on the
remote host does not sanitize input to the 'i' parameter of the
'handler_image.php' script before using it to generate dynamic HTML.

An attacker can leverage this issue to inject arbitrary HTML or script
code into a user's browser to be executed within the security context
of the affected site.");
  script_set_attribute(attribute:"see_also", value:"https://packetstormsecurity.com/1011-exploits/wpfeedlist-xss.txt");
  script_set_attribute(attribute:"see_also", value:"https://plugins.trac.wordpress.org/changeset/664535/feedlist");
  script_set_attribute(attribute:"solution", value:"Ugrade to version 2.70.00 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin = "FeedList";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "feedlist/readme.txt"][0] =
    make_list('Feed(\\s)?List', 'Bill Rawlinson');

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext     : plugin
  );
}
if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

# Try to exploit the issue.
alert = '<script>alert(\'' + SCRIPT_NAME + '\')</script>';

vuln = test_cgi_xss(
  port     : port,
  cgi      : '/wp-content/plugins/feedlist/handler_image.php',
  dirs     : make_list(dir),
  qs       : 'i='+urlencode(str:alert),
  pass_str : 'for ' + alert + ' cannot be found.',
  pass2_re : '^Cached file for '
);
if (!vuln)
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
