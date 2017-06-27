#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62204);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/09/20 00:52:09 $");

  script_name(english:"HP Database Archiving Software Detection");
  script_summary(english:"Looks for the login page.");

  script_set_attribute(attribute:"synopsis", value:
"A database archiving software web console is running on the remote
host.");
  script_set_attribute(attribute:"description", value:
"HP Database Archiving Software, a web interface for managing database
archives, is running on the remote host.");
  # http://www8.hp.com/us/en/software-solutions/software.html?compURI=1175612#.UFI37q7F3X5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e8976b9");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:database_archiving_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 443, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

# Get the ports that web servers have been found on, defaulting to 8080
port = get_http_port(default:8080);

# Put together a list of directories we should check in.
dirs = make_list();
dirs[0] = '/WebConsole/login/auth';

# Put together checks for different pages that we can scrape version
# information from.
checks = make_array();

regexes = make_list();
regexes[0] = make_list(
  '<title>HP Database Archiving - Login</title>'
);
regexes[1] = make_list(
  "<a href=./WebConsole/help/about.*>(\d+.\d+.\d+)</a>"
);

checks["/"] = regexes;

# Find where the web interface is installed.
installs = find_install(appname:"hp_database_archiving_software", checks:checks, dirs:dirs, port:port);
if (isnull(installs)) audit(AUDIT_NOT_DETECT, "HP Database Archiving Software", port);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "HP Database Archiving Software",
    installs     : installs,
    port         : port
  );
}
security_note(port:port, extra:report);
