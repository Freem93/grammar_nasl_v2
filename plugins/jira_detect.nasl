#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45577);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/08/04 14:48:27 $");

  script_name(english:"Atlassian JIRA Detection");
  script_summary(english:"Checks for the JIRA dashboard.");

  script_set_attribute(attribute:"synopsis", value:
"An issue tracker is running on the remote web server.");
  script_set_attribute(attribute:"description", value:
"Atlassian JIRA, a web-based issue tracker written in Java, is running
on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.atlassian.com/software/jira/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

app = "Atlassian JIRA";
# Put together a list of directories we should check for JIRA in.
dirs = cgi_dirs();

if (thorough_tests)
{
  dirs = make_list(dirs, "/jira");
  dirs = list_uniq(dirs);
}

# Put together checks for different pages that we can scrape version
# information from.
checks = make_array();

# This covers older versions.
regexes = make_list();
regexes[0] = make_list("please notify your JIRA administrator of this problem");
regexes[1] = make_list(">Version *: ([0-9.]+)");
checks["/500page.jsp"] = regexes;

# This covers newer versions.
regexes = make_list();
regexes[0] = make_list(
  '<a +href="http://www\\.atlassian\\.com/software/jira" +class="smalltext" *>Atlassian +JIRA</a *>'
);
regexes[1] = make_list(
  '<meta +name="ajs-version-number" +content="([0-9.]+)" *>',
  '<input +type="hidden" +title="JiraVersion" +value="([0-9.]+)" */>',
  '<span +id="footer-build-information"[^>]*>\\(v([0-9.]+)[^<]+</span *>',
  "Version *: *([0-9.]+)"
);
checks["/login.jsp"] = regexes;

# This covers the REST API for the 4.x series.
regexes = make_list();
regexes[0] = make_list('"baseUrl" *:', '"version" *:', '"scmInfo" *:');
regexes[1] = make_list('"version" *: *"([0-9.]+)"');
checks["/rest/api/2.0.alpha1/serverInfo"] = regexes;

# This covers the REST API for the 5.x series.
checks["/rest/api/2/serverInfo"] = regexes;

# Get the ports that webservers have been found on, defaulting to
# JIRA's default port.
port = get_http_port(default:8080);

# Find where JIRA is installed.
installs = find_install(appname:app, checks:checks, dirs:dirs, port:port);

if (isnull(installs))
  audit(AUDIT_WEB_APP_NOT_INST, app, port);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : app,
    installs     : installs,
    port         : port
  );
}

security_note(port:port, extra:report);
