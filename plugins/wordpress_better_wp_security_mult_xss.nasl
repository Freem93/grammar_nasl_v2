#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73271);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/16 03:36:09 $");

  script_cve_id("CVE-2012-4263", "CVE-2012-4264");
  script_bugtraq_id(53480);
  script_osvdb_id(84737, 84738);

  script_name(english:"Better WP Security Plugin for WordPress Multiple XSS");
  script_summary(english:"Checks version of Better WP Security plugin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The WordPress Better WP Security Plugin installed on the remote host
is affected by multiple cross-site scripting (XSS) vulnerabilities :

  - The application fails to properly sanitize user-supplied
    input to the HTTP_USER_AGENT header. (CVE-2012-4263)

  - The application fails to properly sanitize user-supplied
    input to unspecified server variables. (CVE-2012-4264)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://packetstormsecurity.com/files/112617/WordPress-Better-WP-Security-Cross-Site-Scripting.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5166c758");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/plugins/better-wp-security/changelog/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bit51:better-wp-security");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
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

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin = "Better WP Security";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('Better WP Security', '"Project-Id-Version:');
  checks["/wp-content/plugins/better-wp-security/languages/better-wp-security.pot"] = regexes;

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
  item         : dir + "/wp-content/plugins/better-wp-security/readme.txt",
  port         : port,
  exit_on_fail : TRUE
);

if (
  '=== Better WP Security ===' >< res[2] &&
  'Stable tag:' >< res[2] &&
  'Tested up to:' >< res[2]
)
{
  version = UNKNOWN_VER;
  # Grab version
  match = eregmatch(pattern:"Stable tag: ([0-9\.]+)", string:res[2]);
  if (!isnull(match)) version = match[1];
}
else exit(0, "Failed to read the 'readme.txt' file for the WordPress " + plugin + " plugin located at " + install_url + ".");

fix = '3.2.5';
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
