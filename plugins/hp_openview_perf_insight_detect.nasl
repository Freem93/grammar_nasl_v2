#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51849);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/09 00:11:22 $");

  script_name(english:"HP OpenView Performance Insight Server Detection");
  script_summary(english:"Looks for the HP OVPI login page");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A performance monitoring application was detected on the remote web
server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The web interface for HP OpenView Performance Insight was detected on
the remote host.  This software helps assess the availability and
performance of network services."
  );
  # http://www8.hp.com/us/en/software/enterprise-software.html?zn=bto&cp=1-11-15-119^1211_4000_100__
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba1ee862");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:openview_performance_insight");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
installs = NULL;

# the software is designed to serve the app out of the root
dir = '';
url = dir + '/';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if (
  '<h1>HP Performance Insight</h1>' >< res[2] &&
  'alt="HP OpenView Performance Insight Login"'
)
{
  ver = NULL;
  match = eregmatch(string:res[2], pattern:'<h4>Version ([0-9.]+)', icase:TRUE);
  if (match) ver = match[1];

  installs = add_install(
    installs:installs,
    dir:dir,
    ver:ver,
    appname:'hp_ovpi',
    port:port
  );
}

if (isnull(installs))
  exit(0, 'HP OVPI wasn\'t detected on port '+port+'.');

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'HP OpenView Performance Insight',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);

