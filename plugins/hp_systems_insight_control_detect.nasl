#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50539);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/29 21:03:42 $");

  script_name(english:"HP Systems Insight Control Detection");
  script_summary(english:"Checks for HP Insight Control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is running software that allows
administrators to remotely control aspects of a host's environment.");

  script_set_attribute(attribute:"description", value:
"HP Systems Insight Control implements infrastructure management and
has the ability to deploy, migrate, monitor, control, and optimize IT
infrastructure through a management console.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38f199f5");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:insight_control");
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

# Since this is initialized to NULL, the first time add_install() is called, it
# will create a new array with the given key-value pair
installs = NULL;

url = '/';
res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);

if (
  '<title>HP Insight Control</title>' >< res &&
  '<html class="signInPage">' >< res &&
  '<td class="signInTitle"><h1>HP Insight Control</h1></td>' >< res
)
{
  installs = add_install(
    installs:installs,
    dir:url,
    ver:NULL,
    appname:'hp_insight_control',
    port:port
  );
}
if (isnull(installs)) exit(0, "HP Systems Insight Control wasn't detected on port " + port + ".");

if (report_verbosity > 0)
{
  # Note the 'item' argument can be omitted since the application was detected in '/'
  report = get_install_report(
    display_name:'HP Systems Insight Control',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
