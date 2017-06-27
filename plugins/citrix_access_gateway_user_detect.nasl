#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65951);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/04/13 00:13:37 $");

  script_name(english:"Citrix Access Gateway User Web Interface Detection");
  script_summary(english:"Looks for the Citrix Access Gateway user interface.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web interface for users.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts the web interface for using Citrix Access
Gateway, an SSL VPN appliance.");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/product/ag/v5.0/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:access_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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

app = "Citrix Access Gateway User Web Interface";

# Put together a list of directories we should check for CAG in.
#
# Prioritize the root of the server. This is only necessary because of
# enabling redirects. We need them on to find the logon point, but the
# webapp framework may register a directory that won't work for other
# plugins that depend on this one.
dirs = list_uniq(make_list("", cgi_dirs()));

# Put together checks for different pages that we can confirm the
# name of the software from.
checks = make_nested_array(
  # This will find v4 instances, which have little to identify them.
  "/", make_nested_list(
    make_list(
      '<img +src *= *"/000_header_black_logo.gif"[^>]*>',
      '<img +src *= *"/000_citrixwatermark.gif"[^>]*>'
    ),
    make_list()
  ),

  # This will find v5 instances, which have more to identify them.
  "/lp", make_nested_list(
    make_list(
      '<title> *Citrix +Access +Gateway *</title>',
      '<div +id *= *"AGContentBox"[^>]*>'
    ),
    make_list()
  )
);

# Get the ports that webservers have been found on, defaulting to
# CAG's default HTTPS port for the user interface.
port = get_http_port(default:443);

# Find where CAG is installed.
#
# v5 installs perform multiple redirects, and fail to have anything
# shown if there is no default login point.
installs = find_install(appname:"citrix_access_gateway_user", checks:checks, dirs:dirs, port:port, follow_redirect:3);
if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, app, port);

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
