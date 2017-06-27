#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(50541);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/09 00:11:22 $");

  script_name(english:"HP Systems Insight Manager Detection");
  script_summary(english:"Checks for HP Systems Insight Manager");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application for remotely managing
systems.");

  script_set_attribute(attribute:"description", value:
"HP Systems Insight Manager, a web-based application for managing
remote systems, is installed on the remote host.");

  script_set_attribute(attribute:"see_also", value:"http://h18000.www1.hp.com/products/servers/management/hpsim/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:systems_insight_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 50000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:50000);

installs = NULL;

res = http_get_cache(item:'/', port:port, exit_on_fail:TRUE);

if (
  '<title>HP Systems Insight Manager</title>' >< res &&
  '<html class="signInPage">' >< res &&
  '<td class="signInTitle"><h1>HP Systems Insight Manager</h1></td>' >< res
)
{
  installs = add_install(
    installs:installs,
    dir:'/',
    appname:'hp_insight_manager',
    port:port
  );
}
if (isnull(installs)) exit(0, "HP Systems Insight Manager wasn't detected on port "+port+".");

if (report_verbosity > 0)
{
  # Note the 'item' argument can be omitted since the application was detected in '/'
  report = get_install_report(
    display_name:'HP Systems Insight Manager',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
