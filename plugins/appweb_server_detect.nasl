#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61395);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/27 14:49:39 $");
  
  script_name(english:"Appweb HTTP Server Version");
  script_summary(english:"Obtains the version of the remote Appweb HTTP Server");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the version number of the remote Appweb HTTP
server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running the Appweb HTTP Server, an open source web
server.  It was possible to read its version number from the banner. 

Note that 'Embedthis' used to be known as 'Mbedthis' and 'Appweb' used
to be known as 'AppWeb'.");
  script_set_attribute(attribute:"see_also", value:"https://embedthis.com/appweb/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
 
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/02");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:mbedthis_software:mbedthis_appweb_http_server");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");

  script_dependencies("http_version.nasl");
  script_require_ports(80, 7777, "Services/www");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("http_misc_func.inc");

port = get_http_port(default:80);

server_header = http_server_header(port:port);
if (isnull(server_header)) exit(0, "The web server listening on port "+port+" does not return a Server response header.");

server_header = chomp(server_header);

if (
  ("-appweb" >!< tolower(server_header)) &&
  ("embedthis-" >!< tolower(server_header))
) audit(AUDIT_WRONG_WEB_SERVER, port, "Appweb");

set_kb_item(name:"www/"+port+"/appweb", value:TRUE);

matches = eregmatch(
  pattern : "^(Mbedthis-AppWeb|Embedthis-Appweb|Embedthis-http)\/([^ ]+)",
  string  : server_header,
  icase   : TRUE
);
if (isnull(matches)) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "Appweb", port);

version = matches[2];
set_kb_item(name:"www/appweb/"+port+"/version", value:version);
set_kb_item(name:"www/appweb/"+port+"/source", value:server_header);

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + server_header + 
    '\n  Installed version : ' + version +
    '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
