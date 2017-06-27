#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64789);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/01 16:11:56 $");

  script_name(english:"Cisco Prime LAN Management Solution Web Detection");
  script_summary(english:"Looks for the LMS login page");

  script_set_attribute(attribute:"synopsis", value:
"A network management application is hosted on the remote web server.");
  script_set_attribute(attribute:"description", value:
"Cisco Prime LAN Management solution, a network management application,
was detected on the remote web server.");
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/ps11200/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_lan_management_solution");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 443);
  script_dependencies("http_version.nasl");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);

dir = '';
page = '/CSCOnm/servlet/login/login.jsp';
url = dir + page;

res = http_send_recv3(method:'GET', port:port, item:url, exit_on_fail:TRUE);
if ('Login</title>' >!< res[2] || res[2] !~ 'productName=["\'](Cisco )?LAN Management Solution["\']')
  audit(AUDIT_WEB_APP_NOT_INST, 'Cisco Prime LMS', port);

ver = NULL;
match = eregmatch(string:res[2], pattern:'productVersion=["\'](Version )?([0-9.]+)["\']');
if (!isnull(match)) ver = match[2];

install = add_install(
  appname:'cisco_lms',
  dir:dir,
  port:port,
  ver:ver
);

# accessing the document root results in a 403, we'll save the login page so
# any other LMS plugins can use it when they need to report the LMS URL
set_kb_item(name:'/tmp/cisco_lms/' + port + '/loginpage', value:page);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Cisco Prime LAN Management Solution',
    installs:install,
    port:port,
    item:page
  );
  security_note(port:port, extra:report);
}
else security_note(port);

