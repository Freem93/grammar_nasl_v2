#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30109);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/19 18:10:51 $");

  script_cve_id("CVE-2008-0491");
  script_bugtraq_id(27464);
  script_osvdb_id(40916);
  script_xref(name:"EDB-ID", value:"4845");

  script_name(english:"WordPress fGallery 'fim_rss.php' 'album' Parameter SQL Injection");
  script_summary(english:"Attempts to generate a SQL syntax error.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running fGallery, a third-party image gallery
plugin for WordPress.

The version of fGallery installed on the remote host fails to sanitize
input to the 'album' parameter of the 'fim_rss.php' script before
using it in a database query. Regardless of PHP's 'magic_quotes_gpc'
setting, an attacker may be able to exploit this issue to manipulate
database queries, leading to disclosure of sensitive information,
modification of data, or attacks against the underlying database.");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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

plugin = 'fGallery';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('fgallery-plugin', 'msgid "Image Gallery feed');
  checks["/wp-content/plugins/fgallery/languages/fgallery.pot"] = regexes;

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

# Try to exploit the issue to generate a SQL syntax error.
exploit = "-1 " + SCRIPT_NAME + " -- ";

w = http_send_recv3(
  method:"GET",
  item: dir + "/wp-content/plugins/fgallery/fim_rss.php?" +
      "album=" + urlencode(str:exploit),
  port: port,
  exit_on_fail: TRUE
);
res = w[2];

# There's a problem if we see a syntax error.
if ("fim_cat WHERE id = " + exploit + "</code>" >< res)
{
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  security_hole(port);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
