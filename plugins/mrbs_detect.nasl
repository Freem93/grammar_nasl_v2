#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50001);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/09 00:11:23 $");

  script_name(english:"Meeting Room Booking System Detection");
  script_summary(english:"Looks for Meeting Room Booking System");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is running a meeting room booking
system written in PHP."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Meeting Room Booking System, a web-based
room booking system written in PHP."
  );
  script_set_attribute(attribute:"see_also", value:"http://mrbs.sourceforge.net/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

installs = NULL;
ver_pat  = "Meeting Room Booking System<\/a>.*MRBS ([0-9.]+)";

dirs = cgi_dirs();
if (thorough_tests)
{
  dirs = make_list('/mrbs', '/roombooking', '/booking', dirs);
  dirs = list_uniq(dirs);
}

foreach dir (dirs)
{
  url = dir + '/help.php';

  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
  if (!res[2]) continue;

  if (
    (
      '<title>Meeting Room Booking System</title>' >< res[2] &&
      'href="mrbs.css.php" type="text/css">' >< res[2]
    ) ||
    (
      '<TITLE>Meeting Room Booking System</TITLE>' >< res[2] &&
      'href="mrbs.css" type="text/css"' >< res[2]
    )
  )
  {
    ver = NULL;

    matches = eregmatch(pattern:ver_pat, string:res[2], icase:FALSE);
    if (!isnull(matches)) ver = matches[1];

    installs = add_install(
      installs : installs,
      dir      : dir,
      appname  : 'mrbs',
      ver      : ver,
      port     : port
    );

    if (!thorough_tests) break;
  }
}
if (isnull(installs)) exit(0, "Meeting Room Booking System does not appear to be hosted on the web server listening on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Meeting Room Booking System',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
