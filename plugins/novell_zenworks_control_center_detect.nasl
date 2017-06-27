#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58446);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/09 23:56:13 $");

  script_name(english:"Novell ZENworks Control Center Detection");
  script_summary(english:"Looks for the login page");

  script_set_attribute(attribute:"synopsis", value:"A web-based administrative interface was found on the remote host.");
  script_set_attribute(attribute:"description", value:
"Novell ZENworks Control Center, the web-based administrative interface
for Novell ZENworks, was found on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/products/zenworks/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:zenworks");
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

# Put together a list of directories we should check for ZENworks in.
dirs = cgi_dirs();

# Put together checks for different pages that we can scrape version
# information from.
checks = make_array();

# This covers v10.3.
regexes = make_list();
regexes[0] = make_list(
  '<title> *Novell *ZENworks *Control *Center[^<]*</title>',
  '<span[^>]*>[^<]*The ZENworks Control Center requires [^<]* in order to function.[^<]*</span>'
);
regexes[1] = make_list();
checks["/zenworks/jsp/fw/internal/Login.jsp"] = regexes;

# Get the ports that webservers have been found on, defaulting to
# HTTPS.
port = get_http_port(default:443);

# Find where ZENworks the web interface is installed.
installs = find_install(appname:"zenworks_control_center", checks:checks, dirs:dirs, port:port);
if (isnull(installs))
  exit(0, "Novell ZENworks Control Center wasn't detected on port " + port + ".");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "Novell ZENworks Control Center",
    installs     : installs,
    port         : port
  );
}
security_note(port:port, extra:report);
