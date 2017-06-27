#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62787);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/11/01 18:34:57 $");

  script_name(english:"MapServer for Windows (MS4W) Detection");
  script_summary(english:"Looks for MapServer for Windows");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server is running a mapping application."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts MapServer for Windows, a mapping
application that was packaged for Windows installations.  The
application allows MapServer users to install a working environment for
MapServer Development on Windows."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.maptools.org/ms4w/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute: "plugin_publication_date", value:"2012/11/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:maptools:ms4w");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

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

dirs = make_list(cgi_dirs());
checks = make_array();

regexes = make_list();
regexes[0] = make_list("<h1>MS4W - MapServer 4 Windows");
regexes[1] = make_list("version (.+)</h1>", "Welcome to MS4W v(.+),");
checks["/index.phtml"] = regexes;

installs = find_install(appname:"ms4w", checks:checks, dirs:dirs, port:port);

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "MapServer for Windows", port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'MapServer for Windows',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);

