#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58209);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/09 00:11:21 $");

  script_name(english:"Citrix XenServer Web Self Service Detection");
  script_summary(english:"Looks for the login page.");

  script_set_attribute(attribute:"synopsis", value:"A virtual machine management interface is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"Citrix XenServer Web Self Service, a web interface for managing
virtual machines, is running on the remote host.");

  script_set_attribute(attribute:"see_also", value:"http://www.citrix.com/xenserver/");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:citrix:xenserver_web_self_service");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
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

# Put together a list of directories we should check for WSS in.
dirs = cgi_dirs();

# Put together checks for different pages that we can scrape version
# information from.
checks = make_array();

# This covers v1.1.1.
regexes = make_list();
regexes[0] = make_list(
  '<title> *XenServer *Web *Self *Service *</title>',
  'alt *= *" *XenServer *Web *Self *Service *"'
);
regexes[1] = make_list();
checks["/login.mako"] = regexes;

# Get the ports that webservers have been found on, defaulting to
# HTTPS.
port = get_http_port(default:443);

# Find where WSS's web interface is installed.
installs = find_install(appname:"xenserver_web_self_service", checks:checks, dirs:dirs, port:port);

if (isnull(installs))
  exit(0, "Citrix XenServer Web Self Service wasn't detected on port " + port + ".");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "Citrix XenServer Web Self Service",
    installs     : installs,
    port         : port
  );
}
security_note(port:port, extra:report);
