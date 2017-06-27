#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(60080);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/08 22:04:49 $");

  script_name(english:"Eaton Network Shutdown Module Detection");
  script_summary(english:"Looks for evidence of NSM");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server hosts an AC power management application."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server is part of Network Shutdown Module, from Eaton
Corporation (formerly MGE Office Protection Systems).  It is used to
monitor UPS-protected computers and shut them down gracefully if AC
power fails."
  );
  # http://powerquality.eaton.com/Products-services/Power-Management/Software-Drivers/network-shutdown.asp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d32340ff");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:eaton:network_shutdown_module");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 4679);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:4679);


# Unless we're paranoid, make sure it looks like NSM.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port, exit_on_fail:TRUE);
  if (
    "Server: Pi3Web" >!< banner &&
    "Set-Cookie: NSMID=" >!< banner &&
    "Network Shutdown Module" >!< banner
  ) exit(0, "The web server listening on port " + port + " is not from Eaton Network Shutdown Module.");
}


installs = make_array();
url = '/pane_about.php';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (
  'Network Shutdown Module' >< res[2] &&
  '<TITLE>About</TITLE>' >< res[2] &&
  (
    'Eaton Corporation' >< res[2] ||
    'MGE Office Protection Systems' >< res[2]
  )
)
{
  version = NULL;
  if ("Network Shutdown Module</B><BR><B>Version: " >< res[2])
  {
    version = strstr(res[2], "Network Shutdown Module</B><BR><B>Version: ") - "Network Shutdown Module</B><BR><B>Version: ";
    version = version - strstr(version, "<BR>");
  }

  # Save info about the install.
  installs = add_install(
    appname  : "eaton_nsm",
    installs : installs,
    port     : port,
    dir      : '',
    ver      : version
  );
}
else exit(0, "Eaton Network Shutdown Module was not detected on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    item         : '/',
    display_name : "Eaton Network Shutdown Module"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
