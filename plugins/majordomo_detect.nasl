#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51999);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"Majordomo Detection");
  script_summary(english:"Detects Majordomo's web interface");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts a mailing list management application.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host hosts Majordomo, a web-based mailing list management
application."
  );

  script_set_attribute(attribute:"see_also", value:"http://www.greatcircle.com/majordomo/");
  script_set_attribute(attribute:"see_also", value:"http://www.mj2.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

# Put together a list of directories to search through.
if (thorough_tests)
  # Based on a Google search for "inurl:mj_wwwusr".
  dirs = list_uniq(make_list("/mj", "/majordomo", "/lists", cgi_dirs()));
else
  dirs = make_list(cgi_dirs());

# Search for Majordomo.
foreach dir (dirs)
{
  # Request a CGI script.
  url = dir + "/mj_wwwusr";
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  # Majordomo has very little in its HTML to detect.
  if (! ereg(string:res[2], pattern:"<!-- Majordomo [a-zA-Z_]+ format file -->"))
    continue;

  # There is no good way to detect the version of Majordomo that is
  # running.
  version = "unknown";

  if (dir == "") dir = "/";

  installs = add_install(
    appname  : "majordomo",
    installs : installs,
    port     : port,
    dir      : dir,
    ver      : version
  );

  # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
  if (!thorough_tests) break;
}

if (isnull(installs)) exit(0, "Majordomo was not detected on the web server on port " + port + ".");

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : "Majordomo",
    item         : "/mj_wwwusr"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
