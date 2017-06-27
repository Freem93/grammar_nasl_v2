#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59311);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/16 03:36:09 $");

  script_bugtraq_id(53532);

  script_name(english:"Sharebar Plugin for WordPress 'sharebar-admin.php' 'status' Parameter XSS");
  script_summary(english:"Attempts to inject script code via the 'status' parameter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Sharebar plugin for WordPress installed on the
remote host is affected by a cross-site scripting vulnerability due to
a failure properly sanitize user input to the 'status' parameter of
the 'sharebar-admin.php' script before using it to generate dynamic
HTML output. An attacker can leverage this issue to inject arbitrary
HTML and script code into a user's browser to be executed within the
security context of the affected site.

Note that the plugin is reportedly also affected by an associated SQL
injection vulnerability; however, Nessus has not checked for this
issue.");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/extend/plugins/sharebar/changelog/");
  # http://packetstormsecurity.org/files/112690/WordPress-Sharebar-1.2.1-SQL-Injection-Cross-Site-Scripting.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?478b38ef");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/30");

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

plugin = 'Sharebar';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "sharebar/js/sharebar.js"][0] =
    make_list('jQuery\\.fn\\.sharebar');

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

xss_test = '"><script>alert(' + "'" + SCRIPT_NAME + '-' + unixtime() + "'" + ')</script>';

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : '/wp-content/plugins/sharebar/sharebar-admin.php',
  qs       : 'status=' + urlencode(str:xss_test),
  pass_str : 'class="updated fade">' + xss_test,
  pass_re  : '<h2>Custom Sharebar'
);

if (!exploit)
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
