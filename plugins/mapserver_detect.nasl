#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(47860);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/09 00:11:23 $");

  script_name(english:"MapServer Detection");
  script_summary(english:"Checks for MapServer");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts an open source mapping application.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts MapServer, an open source platform for
publishing spatial data and interactive mapping applications to the
web.");
  script_set_attribute(attribute:"see_also", value:"http://mapserver.org/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

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

dirs = cgi_dirs();

installs = NULL;
pat = ".*<!-- MapServer version ((?:\d+\.)*\d+(?:-rc\d+|-beta\d+)?) .*";
foreach dir (dirs)
{
  version = NULL;
  mapserv_cgi = 'mapserv.exe';
  url = dir + '/mapserv.exe?map='+SCRIPT_NAME+'.map';

  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if ("MapServer Message" >!< res[2])
  {
    url = dir+ '/mapserv?map='+SCRIPT_NAME+'.map';
    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
    mapserv_cgi = 'mapserv';
  }

  if (
    'msLoadMap(): Unable to access file. ('+SCRIPT_NAME+'.map)' >< res[2] &&
    egrep(pattern:pat, string:res[2])
  )
  {
    version = ereg_replace(pattern:pat, string:res[2], replace:'\\1');

    installs = add_install(
      installs:installs,
      ver:version,
      dir:dir+'/'+mapserv_cgi,
      appname:'mapserver',
      port:port
    );

    if (!thorough_tests) break;
  }
}

if (isnull(installs)) exit(0, 'MapServer wasn\'t detected on port '+port+'.');

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'MapServer',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
