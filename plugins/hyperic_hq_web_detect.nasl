#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45357);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/09 00:11:22 $");

  script_name(english:"Hyperic HQ Web GUI Detection");
  script_summary(english:"Looks for the login page");

  script_set_attribute(attribute:"synopsis", value:"A web monitoring application was detected on the remote host.");
  script_set_attribute(
    attribute:"description",
    value:
"A web-based interface for Hyperic HQ, a web- and enterprise-
application management system, is running on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.springsource.com/products/hyperic");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 7080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:7080, php:TRUE);

dir = '';
url = dir + '/SignIn.html';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if ('<title>Sign In - Hyperic HQ</title>' >< res[2])
{
  installs = add_install(
    installs:installs,
    dir:dir,
    appname:'hyperic_hq',
    port:port
  );

  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:'Hyperic HQ',
      installs:installs,
      port:port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, 'Hyperic HQ wasn\'t detected on port '+port+'.');

