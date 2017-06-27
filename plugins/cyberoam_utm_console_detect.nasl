#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61446);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/07 17:00:26 $");

  script_name(english:"Cyberoam Admin Console Detection");
  script_summary(english:"Looks for the admin console");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running the console for a security
appliance.");
  script_set_attribute(attribute:"description", value:
"Cyberoam UTM's web admin console is running on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.cyberoam.com/utmoverview.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/h:elitecore:cyberoam_unified_threat_management");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 8090);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

app = "Cyberoam";

# Put together a list of directories we should check in.
dirs = cgi_dirs();

# Put together checks for different pages that we can scrape version
# information from.
checks = make_array();

# This covers an error page in 9.x versions.
regexes = make_list();
regexes[0] = make_list(
  "<TITLE> *Cyberoam *</TITLE>"
);
regexes[1] = make_list(
  "<font[^>]*>([.\d]+ *build *\d+) *</font>"
);
checks["/corporate/webpages/sessionexpired.jsp"] = regexes;

# This covers the main login page, where some 10.x versions pass their
# version as a parameter to JavaScript and CSS.
regexes = make_list();
regexes[0] = make_list(
  "<title> *(Cyberoam|::: *Welcome *To *Cyberoam *- *Please *Login *:::) *</title>"
);
regexes[1] = make_list(
  '<(?:[Ll][Ii][Nn][Kk]|script)[^>]*(?:[Hh][Rr][Ee][Ff]|src)="[^"]*\\?ver(?:sion)?=([.\\d]+ *build *\\d+)"[^>]*>'
);
checks["/corporate/webpages/login.jsp"] = regexes;

# Get the ports that webservers have been found on.
port = get_http_port(default:80);

# Find installations.
installs = find_install(appname:"cyberoam", checks:checks, dirs:dirs, port:port);

if (isnull(installs))
  audit(AUDIT_NOT_DETECT, app, port);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "Cyberoam UTM",
    installs     : installs,
    port         : port
  );
}

security_note(port:port, extra:report);
