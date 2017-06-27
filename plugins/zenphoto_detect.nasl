#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49287);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/09 00:11:26 $");

  script_name(english:"Zenphoto Detection");
  script_summary(english:"Looks for Zenphoto");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is running a photo gallery system written in
PHP."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Zenphoto, a web-based photo gallery system
written in PHP."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zenphoto.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zenphoto:zenphoto");
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

port = get_http_port(default:80, php: TRUE);

installs    = NULL;
dirs        = cgi_dirs();
ver_comment_pat  = "<!-- zenphoto version ([0-9.]+) (\[|r-)([0-9]+)";
ver_comment_pat2 = "<!-- zenphoto version ([0-9.]+)";

if (thorough_tests)
{
  dirs = make_list(dirs, '/zenphoto', '/gallery', '/photos', '/album');
  dirs = list_uniq(dirs);
}

foreach dir (dirs)
{
  ver = NULL;
  matches = NULL;

  url = dir + '/';
  res = http_send_recv3(method: "GET", item: url, port: port, exit_on_fail: TRUE);

  if ( '<!-- zenphoto version' >< res[2])
  {
    matches = eregmatch(pattern:ver_comment_pat , string:res[2], icase:FALSE);

    if (!matches)
      matches = eregmatch(pattern:ver_comment_pat2 , string:res[2], icase:FALSE);

    ver = matches[1];

    if (matches[3])
      ver = ver + ' ' + matches[3]; # include build number
  }
  else if (
    'Powered by <a href="http://www.zenphoto.org" title="' >< res[2] ||
    'Powered by Zenphoto' >< res[2]
  )
    ver = NULL;
  else
    continue;

  # Make sure this is not a gallery page inside an install
  if (egrep(string:res[2], pattern: '<link rel=\\"alternate\\" type=\\"application\\/rss\\+xml.*albumtitle=.*albumname=')) continue;

  installs = add_install(
    installs : installs,
    dir      : dir,
    appname  : 'zenphoto',
    ver      : ver,
    port     : port
  );

  if (!thorough_tests) break;
}

if (isnull(installs)) exit(0, "Zenphoto wasn't detected on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Zenphoto',
    installs     : installs,
    port         : port
  );
  security_note(port: port, extra: report);
}
else security_note(port);
