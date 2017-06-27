#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82827);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/17 13:32:19 $");

  script_bugtraq_id(73930);
  script_osvdb_id(120315);

  script_name(english:"WP Super Cache Plugin for WordPress wp-cache.php Cache List Content Handling XSS");
  script_summary(english:"Checks the version of the WP Super Cache plugin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by
a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WordPress WP Super Cache Plugin hosted on the remote web server
is affected by a cross-site scripting (XSS) vulnerability due to a
failure to properly sanitize user-supplied input when handling cache
list content in the 'wp-cache.php' script. A remote, unauthenticated
attacker can exploit this issue to inject arbitrary script code within
a user's browser session.

Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  # http://blog.sucuri.net/2015/04/security-advisory-persistent-xss-in-wp-super-cache.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40d5e9d1");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/plugins/wp-super-cache/changelog/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin = 'WP Super Cache';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "wp-super-cache/wp-super-cache.pot"][0] =
    make_list('WP Super Cache configuration file');

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

res = http_send_recv3(
  method       : "GET",
  item         : dir + "/wp-content/plugins/wp-super-cache/readme.txt",
  port         : port,
  exit_on_fail : TRUE
);

if (
  '=== WP Super Cache ===' >< res[2] &&
  'Stable tag:' >< res[2] &&
  'Tested up to:' >< res[2]
)
{
  version = UNKNOWN_VER;
  # Grab version
  match = eregmatch(pattern:"Stable tag: ([0-9\.]+)", string:res[2]);
  if (!empty_or_null(match)) version = match[1];
}
else exit(0, "Failed to read the 'readme.txt' file for the "+app+ " " + plugin + " plugin located at " + install_url);

if (version == UNKNOWN_VER)
  exit(0, "Unable to determine the version of the " +plugin+ " plugin located on the " +app+ " install at " +install_url);

fix = '1.4.3';
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : ' +fix + '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + ' plugin', version);
