#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67006);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/28 00:22:00 $");

  script_name(english:"Sybase EAServer Detect");
  script_summary(english:"Checks for Sybase EAServer");

  script_set_attribute(attribute:"synopsis", value:"An application server is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Sybase EAServer, an application server, is installed on the remote
host.");
  script_set_attribute(attribute:"see_also", value:"http://www.sybase.com/products/modelingdevelopment/easerver");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sybase:easerver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8000, 8001);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = 'Sybase EAServer';

port = get_http_port(default:8000);

installs = NULL;
version = UNKNOWN_VER;

banner = get_http_banner(port:port, exit_on_fail:TRUE);

headers = parse_http_headers(status_line:banner, headers:banner);
if (isnull(headers)) exit(1, 'Error processing HTTP response headers from the web server on port ' + port + '.');

server = headers['server'];
if (isnull(server)) exit(1, 'The web server on port '+port+' doesn\'t send a Server response header.');

if ('Jetty(EAServer' >< server)
{
  pattern = 'Jetty\\(EAServer/([0-9\\.]+ Build [0-9\\.]+)';
  match = eregmatch(string:server, pattern:pattern, icase:TRUE);
  if (match) version = match[1];

  set_kb_item(name:'www/'+port+'/sybase_easerver/Source', value:server);
  installs = add_install(
    installs:installs,
    dir:'',
    ver:version,
    appname:'sybase_easerver',
    port:port
  );

  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:'Sybase EAServer',
      installs:installs,
      port:port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_NOT_DETECT, 'Sybase EAServer', port);
