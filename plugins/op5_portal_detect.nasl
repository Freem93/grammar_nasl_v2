#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57575);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/08 22:04:49 $");

  script_name(english:"op5 Portal Detection");
  script_summary(english:"Looks for an op5 Portal instance.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts a PHP portal application.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts op5 Portal, a web interface platform that
contains several other components produced by op5, notably op5
Monitor.");
  script_set_attribute(attribute:"see_also", value:"http://www.op5.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/17");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:op5:system-portal");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

# Put together a list of directories we should check for op5 in.
dirs = cgi_dirs();

# Put together checks for different pages that we can scrape version
# information from.
checks = make_array();

regexes = make_list();
regexes[0] = make_list("Current op5 System version");
regexes[1] = make_list("Current op5 System version: *<strong> *([0-9.]+)");
checks["/about.php"] = regexes;

# Get the ports that webservers have been found on, defaulting to
# op5's default HTTPS port.
port = get_http_port(default:443);

# Find where op5 is installed.
installs = find_install(appname:"op5_portal", checks:checks, dirs:dirs, port:port);

if (isnull(installs))
  exit(0, "op5 Portal wasn't detected on port " + port + ".");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "op5 Portal",
    installs     : installs,
    port         : port
  );
}
security_note(port:port, extra:report);
