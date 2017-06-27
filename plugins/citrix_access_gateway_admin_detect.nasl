#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65949);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/04/13 00:13:37 $");

  script_name(english:"Citrix Access Gateway Administrative Web Interface Detection");
  script_summary(english:"Looks for the Citrix Access Gateway admin interface.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts an administrative web interface.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts the web interface for administering Citrix
Access Gateway, an SSL VPN appliance.");
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
  script_require_ports("Services/www", 443, 9001);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

app = "Citrix Access Gateway Administrative Web Interface";

# Put together a list of directories we should check for CAG in.
dirs = cgi_dirs();

# Put together checks for different pages that we can confirm the
# name of the software from.
checks = make_nested_array(
  # This will find v4 instances, which have little to identify them.
  "/", make_nested_list(
    make_list(
      '<span +dist *= *"ag,uber,vpn"[^>]*>',
      # Yes, there are two title tags on the page.
      '<title>Administration Tool</title>',
      '<title>Administration Portal</title>'
    ),
    make_list()
  ),

  # This will find v5 instances, which have much to identify them.
  "/lp/AdminlogonPoint/Logon.do", make_nested_list(
    make_list(
      '<title> *Citrix +Access +Gateway *</title>',
      '<!-- *CONTENT +CONTENT +CONTENT +CONTENT +CONTENT *-->',
      '<div +id="AGContentBox"[^>]*>'
    ),
    make_list()
  )
);

# Get the ports that webservers have been found on, defaulting to
# CAG's default HTTPS port after v5.
port = get_http_port(default:443);

# Find where CAG is installed.
installs = find_install(appname:"citrix_access_gateway_admin", checks:checks, dirs:dirs, port:port);
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
