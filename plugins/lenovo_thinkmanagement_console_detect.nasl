#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58653);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/09 00:11:23 $");

  script_name(english:"Lenovo ThinkManagement Console Detection");
  script_summary(english:"Looks for a known file.");

  script_set_attribute(attribute:"synopsis", value:"A web-based API was found on the remote host.");
  script_set_attribute(attribute:"description", value:
"Lenovo ThinkManagement Console, a web-based API for Lenovo
ThinkManagement, was found on the remote host.");

  script_set_attribute(attribute:"see_also", value:"http://www.landesk.com/lenovo/thinkmanagement-console.aspx");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:landesk:lenovo_thinkmanagement_console");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

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

# Put together a list of directories we should check for
# ThinkManagement in.
dirs = cgi_dirs();

# Put together checks for different pages that we can scrape version
# information from.
checks = make_array();

regexes = make_list();
regexes[0] = make_list(
  "MENU LABEL LANDesk\(R\) Managed WinPE"
);
regexes[1] = make_list();
checks["/landesk/vboot/default.winpemanaged"] = regexes;

# Get the ports that webservers have been found on, defaulting to
# HTTP.
port = get_http_port(default:80);

# Find where ThinkManagement Console is installed.
installs = find_install(appname:"thinkmanagement_console", checks:checks, dirs:dirs, port:port);
if (isnull(installs))
  exit(0, "Lenovo ThinkManagement Console wasn't detected on port " + port + ".");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "Lenovo ThinkManagement Console",
    installs     : installs,
    port         : port
  );
}
security_note(port:port, extra:report);
