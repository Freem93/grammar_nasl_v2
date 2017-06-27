#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66718);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/05/31 14:49:16 $");

  script_name(english:"Greenstone Detection");
  script_summary(english:"Looks for Greenstone's library.cgi");

  script_set_attribute(attribute:"synopsis", value:"The remote web server contains a digital library software product.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts Greenstone, a web-based software suite for
creating and managing digital library collections.");
  script_set_attribute(attribute:"see_also", value:"http://www.greenstone.org/");
  script_set_attribute(attribute:"solution", value:"n/a" );
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:greenstone:greenstone");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/greenstone", "/gsdl", cgi_dirs()));
else dirs = make_list(cgi_dirs());

checks = make_array();
regexes = make_list();
regexes[0] = make_list("<title>Greenstone Digital Library Software</title>", 'href="http://greenstone.org"', '>About Greenstone</a>');
regexes[1] = make_list(  '<meta name="Greenstone version number" content="(.+)"');
checks['/cgi-bin/library.cgi'] = regexes;

installs = find_install(appname:"greenstone", checks:checks, dirs:dirs, port:port);
if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "Greenstone", port);

if( report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Greenstone',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
} else security_note(port);
