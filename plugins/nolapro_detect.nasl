#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46703);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/09 00:11:23 $");

  script_name(english:"NolaPro Detection");
  script_summary(english:"Checks for NolaPro Web Application");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web-based business management
application written in PHP");

  script_set_attribute(attribute:"description", value:
"The remote web server hosts NolaPro, a web-based business management
application written in PHP.");

  script_set_attribute(attribute:"see_also", value:"http://www.nolapro.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 50080);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:50080, php:TRUE);

login_page = '/index.php';
res = http_get_cache(item:login_page, port:port, exit_on_fail:TRUE);
if (
  '<title>NolaPro Login</title>' >< res &&
  'Web-Based Business Management' >< res
)
{
  install = add_install(
    dir:'/',
    appname:'nolapro',
    port:port
  );

  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:"NolaPro",
      installs:install,
      item:login_page,
      port:port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, "NolaPro wasn't detected on port " + port + ".");
