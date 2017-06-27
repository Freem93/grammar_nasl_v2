#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66720);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/05/31 16:03:51 $");

  script_name(english:"Junos Space WebUI Detection");
  script_summary(english:"Looks for Space login page");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The web interface for a network management application was detected on
the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Junos Space is a network management solution used to automate
management for Juniper hardware.  Junos Space WebUI, the web interface
for Junos Space, was detected on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.juniper.net/products-services/network-management/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
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

dir = '/mainui';
page = '/';
url = dir + page;
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);
if ('<title class="loginTitle"> Junos Space Login</title>' >!< res[2])
  audit(AUDIT_WEB_APP_NOT_INST, 'Junos Space WebUI', port);

install = add_install(appname:'junos_space', dir:dir, port:port);

if (report_verbosity > 0)
{
  report = get_install_report(installs:install, port:port, display_name:'Junos Space WebUI');
  security_note(port:port, extra:report);
}
else security_note(port);
