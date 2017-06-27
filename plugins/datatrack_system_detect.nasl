#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46865);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/11 13:46:37 $");

  script_name(english:"Magnoware DataTrack System Detection");
  script_summary(english:"Looks for the DataTrack System login page");

  script_set_attribute(attribute:"synopsis", value:"A help desk software is hosted on the remote web server.");
  script_set_attribute(attribute:"description",value:
"DataTrack System, a web-based support management system
from Magnoware, is installed on the remote web server.");

  script_set_attribute(attribute:"see_also", value:"http://magnoware.com/products/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP","www/magnoware");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80,asp:TRUE);

dir = '';
page = '/Home.aspx';
installs = NULL;

url = dir+page;
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if (
  '<title>DataTrack Web Client</title>' >< res[2]          &&
  'cssTextTitle">Login or Create Account</span>' >< res[2] &&
  'SubTitle">Specify your username and password to login' >< res[2]
)
{
  installs = add_install(
    installs:installs,
    dir:dir,
    appname:'datatrack_system',
    port:port
  );

  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:'DataTrack System',
      installs:installs,
      item:page,
      port:port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);

  exit(0);
}
else exit(0, 'DataTrack System was not detected on port '+port+'.');
