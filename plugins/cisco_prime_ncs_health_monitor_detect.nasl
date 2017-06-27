#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69056);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/08/30 18:00:41 $");

  script_name(english:"Cisco Prime Network / Wireless Control System Health Monitor Detection");
  script_summary(english:"Looks for Health Monitor login page");

  script_set_attribute(
    attribute:"synopsis",
    value:"A web management interface was detected on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The web interface for Cisco Prime Network / Wireless Control System
Health Monitor was detected on the remote host.  Health Monitor is
used to manage the high availability implementation for Network /
Wireless Control System."
  );
  # http://www.cisco.com/en/US/products/ps10315/products_tech_note09186a0080bba943.shtml#high
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37ba0995");
  #http://www.cisco.com/en/US/docs/wireless/wcs/release/notes/WCS_RN7_0_230.html#wp92167
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dffc3924");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_network_control_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8082);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8082);
dir = '';
page = '/login.jsp';
res = http_send_recv3(method:'GET', item:page, port:port, exit_on_fail:TRUE);

if (
  ('Health Monitor Login Page' >!< res[2]) || 
  ('>Health Monitor<' >!< res[2]) 
)
{
  audit(AUDIT_WEB_APP_NOT_INST, 'Prime NCS / WCS Health Monitor', port);
}

install = add_install(
  appname:'prime_health_monitor',
  dir:dir,
  port:port
);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Cisco Prime NCS / WCS Health Monitor',
    installs:install,
    port:port,
    item:page
  );
  security_note(port:port, extra:report);
}
else security_note(port);
