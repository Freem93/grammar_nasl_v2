#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52457);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_bugtraq_id(46482);
  script_osvdb_id(71044);

  script_name(english:"Comment Rating Plugin for WordPress 'id' Parameter SQL Injection");
  script_summary(english:"Attempts to generate a SQL error.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is prone to a SQL
injection attack.");
  script_set_attribute(attribute:"description", value:
"The version of the Comment Rating plugin for WordPress hosted on the
remote web server fails to sanitize input to the 'id' parameter of the
'ck-processkarma.php' script before using it in a database query.

Regardless of PHP's 'magic_quotes_gpc' setting, an unauthenticated
remote attacker can leverage this issue to manipulate database
queries, resulting in the disclosure of sensitive information or
attacks against the underlying database.");
  # http://www.htbridge.ch/advisory/sql_injection_in_comment_rating_wordpress_plugin.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?994cf1ca");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Feb/224");
  # http://web.archive.org/web/20110806014404/http://wordpress.org/extend/plugins/comment-rating/changelog/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1e62f2d");
  script_set_attribute(attribute:"solution", value:"Upgrade to Comment Rating version 2.9.24 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

plugin = "Comment Rating";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "comment-rating/ck-karma.js"][0] =
    make_list('Plugin Name: Comment Rating');

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

# Try to exploit the issue to generate a SQL error.
magic1 = "-" + rand() % 1000;
magic2 = SCRIPT_NAME;

exploit = magic1 + ' ' + magic2;
url = dir + '/wp-content/plugins/comment-rating/ck-processkarma.php?' +
  'path=1&' +
  'action=add&' +
  'id=' + str_replace(find:" ", replace:"%20", string:exploit);

res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

if (
  'error|mysql: ' >< res[2] &&
  "SQL syntax" >< res[2] &&
  magic2 >< res[2]
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    header =
      'Nessus was able to verify the issue by manipulating the database \n' +
      'query and generating a SQL error using the following URL :';
    report = get_vuln_report(items:url, port:port, header:header);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
