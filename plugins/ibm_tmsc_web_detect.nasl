#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44394);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/08/09 00:11:23 $");

  script_name(english:"IBM Tivoli Monitoring Service Console Detection");
  script_summary(english:"Checks for the Tivoli Monitoring Service Console Index page");

  script_set_attribute(attribute:"synopsis", value:"A system monitoring console was detected on the remote web server.");
  script_set_attribute(
    attribute:"description",
    value:
"Tivoli Monitoring Service Console, a web interface for running system
diagnostics, is hosted on the remote web server.  This software is
included with some IBM products, such as DB2."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/software/tivoli/products/monitor/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_monitoring");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 1920, 3661);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:1920);

# Extract the version/build from the banner
banner = get_http_banner(port:port);
if (isnull(banner)) exit(1, 'Unable to get banner from the web server on port '+port+'.');

headers = parse_http_headers(status_line:banner, headers:banner);
if (isnull(headers)) exit(1, 'Error processing HTTP response headers from the web server on port '+port+'.');

server = headers['server'];
if (isnull(server)) exit(0, "The web server on port "+port+" doesn't send a Server response header.");

match = eregmatch(string:server, pattern:'^KDH/(.+)$');
if (!match) exit(0, "The web server on port "+port+" doesn't appear to be Tivoli Monitoring Service console.");

# Make sure this looks like the Monitoring Service Console
res = http_get_cache(item:'/', port:port, exit_on_fail: 1);

if ('><title>IBM Tivoli Monitoring Service Index</title>' >< res)
{
  installs = add_install(
    dir:'/',
    ver:match[1],
    appname:'tmsc',
    port:port
  );

  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:'Tivoli Monitoring Service Console',
      installs:installs,
      port:port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, "Tivoli Monitoring Service Console wasn't detected on port "+port+".");

