#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46221);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/03/03 18:58:53 $");

  script_name(english:"Cacti Detection");
  script_summary(english:"Looks for the Cacti login page");

  script_set_attribute(attribute:"synopsis", value:
"A graphing application was detected on the remote web server.");
  script_set_attribute(attribute:"description", value:
"Cacti, a web-based front-end for RRDtool, was detected on the remote
host.

RRDtool tracks system statistics such as CPU load and network
bandwidth.");
  script_set_attribute(attribute:"see_also", value:"http://www.cacti.net/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);
installs = NULL;
pattern = 'Cacti CHANGELOG[ \t\r\n]+([0-9a-z.]+)';
dirs = cgi_dirs();

if (thorough_tests)
{
  dirs = make_list(dirs, '/cacti');
  dirs = list_uniq(dirs);
}

foreach dir (dirs)
{
  url = dir+'/index.php';
  res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);

  if ('<title>Login to Cacti</title>' >< res)
  {
    # Try to grab the version if possible
    res = http_send_recv3(
      method:'GET',
      item:dir+'/docs/CHANGELOG',
      port:port,
      exit_on_fail:TRUE
    );

    match = eregmatch(string:res[2], pattern:pattern, icase:TRUE);
    if (match) ver = match[1];
    else ver = NULL;

    installs = add_install(
      installs:installs,
      dir:dir,
      ver:ver,
      appname:'cacti',
      port:port
    );

    if (!thorough_tests) break;
  }
}

if (isnull(installs)) exit(0, 'Cacti wasn\'t detected on port '+port+'.');

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Cacti',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
