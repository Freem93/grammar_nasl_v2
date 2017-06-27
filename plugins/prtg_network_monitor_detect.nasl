#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51874);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/09 00:11:24 $");

  script_name(english:"PRTG Network Monitor Detection");
  script_summary(english:"Checks for PRTG Network Monitor");

  script_set_attribute(attribute:"synopsis", value:
"A network traffic monitoring application is hosted on the remote web
server.");

  script_set_attribute(attribute:"description", value:
"PRTG Network Monitor, a web-based tool for displaying network and
bandwidth usage data, is hosted on the remote web server.");

  script_set_attribute(attribute:"see_also", value:"http://www.paessler.com/prtg/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/prtg");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, embedded:TRUE);

installs = NULL;
version = UNKNOWN_VER;

banner = get_http_banner(port:port, exit_on_fail:TRUE);

headers = parse_http_headers(status_line:banner, headers:banner);
if (isnull(headers))
  exit(1, 'Error processing HTTP response headers from the web server on port '+port+'.');

server = headers['server'];
if (isnull(server))
  exit(0, "The web server on port "+port+" doesn't send a Server response header.");

if ('PRTG' >!< server)
  exit(0, "The web server on port "+port+" doesn't appear to be from PRTG Network Monitor.");


matches = eregmatch(pattern:"PRTG/([0-9.]+)",string:server);
if (matches) version = matches[1];

res = http_send_recv3(method:"GET", item:"/index.htm", port:port, exit_on_fail:TRUE);

if ('<title>PRTG Network Monitor ' >< res[2])
{
  installs = add_install(
    installs:installs,
    ver:version,
    dir:'',
    appname:'prtg_network_monitor',
    port:port
  );
}

if (isnull(installs)) exit(0, "PRTG Network Monitor wasn't detected on port "+port+".");

set_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'PRTG Network Monitor',
    installs:installs,
    port:port,
    item: "/index.htm"
  );
  security_note(port:port, extra:report);
}
else security_note(port:port);
