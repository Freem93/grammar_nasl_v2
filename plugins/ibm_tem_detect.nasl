#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66269);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/11/19 17:31:36 $");

  script_name(english:"IBM Endpoint Manager Web Server Detection");
  script_summary(english:"Detects IBM Endpoint Manager Web Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web server for a remote endpoint
management solution.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an IBM Tivoli Endpoint Manager (formerly
BigFix) web server. IBM Endpoint Manager is a software management
solution for networked devices.");
  # http://www-01.ibm.com/software/tivoli/solutions/unified-endpoint-management/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5455c161");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_endpoint_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 52310, 52311, 52312);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app  = "IBM Tivoli Endpoint Manager";

port = get_http_port(default:52311, embedded:FALSE);

server_name = http_server_header(port:port);
if (isnull(server_name)) audit(AUDIT_WEB_NO_SERVER_HEADER, port);
if ("BigFixHTTPServer" >!< server_name) audit(AUDIT_WRONG_WEB_SERVER, port, app);

replace_kb_item(name:"www/BigFixHTTPServer", value:TRUE);
set_kb_item(name:"www/BigFixHTTPServer/"+port+"/installed", value:TRUE);

source  = NULL;
version = UNKNOWN_VER;

pattern = "^BigFixHTTPServer/([0-9\.]+)($|[^0-9\.])";

item = eregmatch(pattern:pattern, string:server_name);
if (!isnull(item[1]))
{
  source  = server_name;
  version = item[1];
}

set_kb_item(name:"www/BigFixHTTPServer/"+port+"/version", value:version);
if (version != UNKNOWN_VER) set_kb_item(name:"www/BigFixHTTPServer/"+port+"/source", value:source);

if (report_verbosity > 0)
{
  info = '';

  if (!empty_or_null(source))
    info += '\n  Source  : ' + source;

  info +=
    '\n  Version : ' + version +
    '\n';
  security_note(port:port, extra:info);
}
else security_note(port);
