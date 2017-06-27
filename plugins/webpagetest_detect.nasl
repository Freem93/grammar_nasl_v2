#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62183);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/09/19 00:47:04 $");

  script_name(english:"WebPagetest Detection");
  script_summary(english:"Looks for WebPagetest");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server is running a web page performance tool."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running WebPagetest, a web-based tool written in PHP
to test website performance."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.webpagetest.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute: "plugin_publication_date", value:"2012/09/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:webpagetest:webpagetest");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

if (thorough_tests) dirs = list_uniq(make_list("/webpagetest", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();

foreach dir (dirs)
{
  url = dir + '/index.php';
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if ("WebPageTest</a></h1>" >< res[2] &&
      'href="http://sites.google.com/a/webpagetest.org' >< res[2]
     )
  {
    # The app does not report version info in a web accessible file
    version = UNKNOWN_VER;

    installs = add_install(
      installs : installs,
      dir      : dir,
      appname  : 'webpagetest',
      ver      : version,
      port     : port
    );
    if (!thorough_tests) break;
  }
}
if (max_index(keys(installs)) == 0) audit(AUDIT_WEB_APP_NOT_INST, "WebPagetest", port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'WebPagetest',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
