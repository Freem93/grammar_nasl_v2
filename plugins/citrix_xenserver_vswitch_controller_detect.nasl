#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58809);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/04/20 15:25:01 $");

  script_name(english:"Citrix XenServer vSwitch Controller Detection");
  script_summary(english:"Looks for the login page.");

  script_set_attribute(attribute:"synopsis", value:
"A virtual switch management interface is running on the remote
host.");
  script_set_attribute(attribute:"description", value:
"Citrix XenServer vSwitch Controller, a web interface for managing
virtual machine networking, is running on the remote host.");

  script_set_attribute(attribute:"see_also", value:"http://www.citrix.com/xenserver/");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:citrix:xenserver_vswitch_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

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

# Put together a list of directories we should check for DVS in.
dirs = cgi_dirs();

# Put together checks for different pages that we can scrape version
# information from.
checks = make_array();

# This covers v2.0.0.
regexes = make_list();
regexes[0] = make_list(
  '<title> *DVS *Controller *</title>',
  '<button[^>]*>Login</button>'
);
regexes[1] = make_list();
checks["/login"] = regexes;

# Get the ports that webservers have been found on, defaulting to
# HTTPS.
port = get_http_port(default:443);

# Find where DVS's web interface is installed.
installs = find_install(appname:"xenserver_vswitch_controller", checks:checks, dirs:dirs, port:port);

if (isnull(installs))
  audit(AUDIT_NOT_DETECT, "Citrix XenServer vSwitch Controller", port);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "Citrix XenServer vSwitch Controller",
    installs     : installs,
    port         : port
  );
}
security_note(port:port, extra:report);
