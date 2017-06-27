#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65892);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/04/10 14:54:43 $");

  script_name(english:"IBM InfoSphere Data Replication Dashboard Detection");
  script_summary(english:"Detects the login page");

  script_set_attribute(
    attribute:"synopsis",
    value:"A status monitoring application is hosted on the remote web server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"IBM InfoSphere Data Replication Dashboard, a component of InfoSphere
Data Replication, is hosted on the remote web server.  This web
application monitors the health of replication and event publishing."
  );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24023065");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:infosphere_replication_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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
dir = '/rdweb';
login_page = '/login/login.html';
url = dir + login_page;

res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);
if ('IBM InfoSphere Data Replication Dashboard requires the Adobe Flash Player' >!< res[2])
  audit(AUDIT_WEB_FILES_NOT, 'InfoSphere Data Replication Dashboard', port);

install = add_install(appname:'ibm_infosphere_data_replication_dashboard', port:port, dir:dir);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'IBM InfoSphere Data Replication Dashboard',
    installs:install,
    item:login_page,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
