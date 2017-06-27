#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57577);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/08 22:04:49 $");

  script_name(english:"op5 Monitor Detection");
  script_summary(english:"Looks for the op5 monitor.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts a PHP application for network monitoring.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts op5 Monitor, a proprietary web interface
for Nagios.");
  script_set_attribute(attribute:"see_also", value:"http://www.op5.com/network-monitoring/op5-monitor/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/17");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:op5:monitor");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("op5_portal_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/op5_portal");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

# Get details of the op5 Portal install.
port = get_http_port(default:443);

install = get_install_from_kb(appname:"op5_portal", port:port, exit_on_fail:TRUE);
dir = install["dir"];

# Request the page from the web server.
url = dir + "/";
res = http_send_recv3(
  port         : port,
  method       : "GET",
  item         : url,
  exit_on_fail : TRUE
);

# Check whether op5 Monitor is installed.
regex = 'Version: *([0-9.]+) *\\| *<a +href="/monitor"';
if (!egrep(string:res[2], pattern:regex))
  exit(0, "op5 Monitor wasn't detected on the web server listening on port " + port + ".");

# Extract the version information.
version = UNKNOWN_VER;
matches = eregmatch(string:res[2], pattern:regex, icase:TRUE);
if (!isnull(matches)) version = matches[1];

# Register the installed instance.
url += "monitor";
installs = add_install(
  installs : NULL,
  port     : port,
  dir      : url,
  appname  : "op5_monitor",
  ver      : version
);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "op5 Monitor",
    installs     : installs,
    port         : port
  );
}

security_note(port:port, extra:report);
