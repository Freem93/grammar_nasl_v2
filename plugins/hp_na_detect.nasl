#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70099);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/09/25 00:03:52 $");

  script_name(english:"HP Network Automation Detection");
  script_summary(english:"Detects HP Network Automation Servers");

  script_set_attribute(
    attribute:"synopsis",
    value:"A web-based management tool is listening on this port."
  );
  script_set_attribute(
    attribute:"description",
    value:"HP Network Automation is running on the remote host."
  );
  # http://www8.hp.com/us/en/software-solutions/software.html?compURI=1169982#.Ujoi9H-TXbc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ac99f14");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:network_automation");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);

dir = '';
page = '/';
url = dir + page;

res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);
if ('<title>HP Network Automation' >!< res) audit(AUDIT_WEB_APP_NOT_INST, 'HP Network Automation', port);

version = NULL;
match = eregmatch(pattern:"<title>HP Network Automation (.*): Login</title>", string:res);
if (!isnull(match)) version = match[1];

install = add_install(
  appname:'hp_network_automation',
  dir:dir,
  port:port,
  ver:version
);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'HP Network Automation',
    installs:install,
    port:port,
    item:page
  );
  security_note(port:port, extra:report);
}
else security_note(port);
