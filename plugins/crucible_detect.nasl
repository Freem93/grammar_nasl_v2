#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59326);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/13 00:06:37 $");

  script_name(english:"Atlassian Crucible Detection");
  script_summary(english:"Looks for the Crucible dashboard.");

  script_set_attribute(attribute:"synopsis", value:"A code review application is hosted on the remote web server.");
  script_set_attribute(attribute:"description", value:
"Atlassian Crucible, a web-based code review application written in
Java, is hosted on the remote web server.");

  script_set_attribute(attribute:"see_also", value:"http://www.atlassian.com/software/crucible/");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:crucible");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8060);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

app = "Crucible";

# Get the ports that webservers have been found on, defaulting to
# what Crucible uses.
port = get_http_port(default:8060);

# Put together checks for different pages that we can scrape version
# information from.
checks = make_array();
installs = NULL;

# This covers the dashboard.
regexes = make_list();
regexes[0] = make_list(
  '<title> *FishEye *[0-9.]+ *</title>',
  'window.FECRU'
);
regexes[1] = make_list(
  'Crucible *([0-9.]+) *with'
);
checks["/"] = regexes;

# This covers the REST API.
regexes = make_list();
regexes[0] = make_list(
  '<versionInfo>.*</versionInfo>'
);
regexes[1] = make_list(
  '<releaseNumber> *([0-9.]+) *</releaseNumber>'
);
checks["/rest-service/reviews-v1/versionInfo"] = regexes;

# Find where Crucible's web interface is installed.
installs = find_install(appname:"crucible", checks:checks, dirs:make_list(''), port:port);

if (isnull(installs))
  audit(AUDIT_WEB_APP_NOT_INST, app, port);

# Report our findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : app,
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
