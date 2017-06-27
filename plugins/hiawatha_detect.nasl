#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69032);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/07/24 11:34:46 $");

  script_name(english:"Hiawatha Detection");
  script_summary(english:"Looks for a Hiawatha");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running a web server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Hiawatha web server, an open source web
server with an emphasis on security.");
  script_set_attribute(attribute:"see_also", value:"http://www.hiawatha-webserver.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/24");

  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:hiawatha:webserver");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

appname = "Hiawatha";

server_header = http_server_header(port:port);
if (isnull(server_header)) exit(0, "The web server listening on port "+port+" does not send a server response header.");
if ("hiawatha" >!< tolower(server_header)) audit(AUDIT_WRONG_WEB_SERVER, port, appname);

match = eregmatch(string: server_header, pattern:"^Hiawatha v(.*)$");
if (isnull(match))
{
  match = eregmatch(string: server_header, pattern:"^Hiawatha/(.*)$");
  if (isnull(match)) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, appname, port);
}
version = match[1];

installs = add_install(
  dir      : "/",
  appname  : "hiawatha",
  ver      : version,
  port     : port
);

if (report_verbosity > 0)
{
  report =
    '\n  Source  : ' + server_header +
    '\n  Version : ' + version +
    '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
