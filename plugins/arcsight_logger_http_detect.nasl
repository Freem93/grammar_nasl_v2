#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69445);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/08/27 20:06:33 $");

  script_name(english:"HP ArcSight Logger HTTP Detection");
  script_summary(english:"Detects HP ArcSight Logger HTTP Interface");

  script_set_attribute(
    attribute:"synopsis",
    value:"HP ArcSight Logger is hosted on the remote HTTP server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host's HTTP server is hosting an HP ArcSight Logger
install, which is used for viewing and managing collected log data."
  );
  # http://www8.hp.com/us/en/software-solutions/software.html?compURI=1314386#.Uf-vYmQ6VX8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d345cf52");
  script_set_attribute(attribute:"solution", value: "Uninstall this software if you do not use it.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/27");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:arcsight_logger");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443, 9000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);

url = '/platform-ui/';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (
  "<title>ArcSight Logger</title>" >!< res[2] &&
  "src='com.arcsight.product.platform.logger.LoggerLauncher.nocache.js'></script>" >!< res[2] &&
  "You must have JavaScript turned on in order to use ArcSight Logger." >!< res[2]
)
audit(AUDIT_WEB_FILES_NOT, "ArcSight Logger", port);

installs = add_install(
  dir      : '/platform-ui',
  appname  : 'arcsight_logger',
  port     : port
);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'ArcSight Logger',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
