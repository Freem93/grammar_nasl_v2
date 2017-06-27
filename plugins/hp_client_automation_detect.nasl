#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(52978);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/09 00:11:22 $");

  script_name(english:"HP Client Automation Web Console Detection");
  script_summary(english:"Checks for HP Client Automation Web Console");

  script_set_attribute(attribute:"synopsis", value:"A web-based management interface was detected on the remote host.");

  script_set_attribute(attribute:"description", value:
"HP Client Automation, a web-based application for managing client
devices, was detected on the remote host.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d63486ab");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:client_automation_administrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 3466);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:3466);

# The login page should always be located at /sessionmanager/login.jsp
login_page = '/sessionmanager/login.jsp';
res = http_send_recv3(method:"GET", item:login_page, port:port, exit_on_fail:TRUE);
if (
  '<title>HP Client Automation' >< res[2] &&
  '<td class="login_appname">Client Automation' >< res[2]
)
{
  install = add_install(dir:'/', appname:'hp_client_automation', port:port);

  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:'HP Client Automation',
      installs:install,
      item:login_page,
      port:port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, 'HP Client Automation wasn\'t detected on port '+port+'.');
