#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58526);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/09 00:11:22 $");

  script_name(english:"HP Data Protector DPNECentral Web Service Detection");
  script_summary(english:"Checks for HP Data Protector DPNECentral Web Service");

  script_set_attribute(attribute:"synopsis", value:"A policy service is hosted on the remote web server.");
  script_set_attribute(attribute:"description", value:
"HP Data Protector DPNECentral Web Service, a component of HP Data
Protector for managing backup policies, is hosted on the remote web
server.

This service is installed with HP Data Protector for PCs, HP Data
Protector Notebook Extension, and possibly other HP Data Protector
software.");
  # http://www8.hp.com/us/en/software-solutions/software.html?compURI=1175640#.UZUHuEpIFXw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9b227f2");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/29");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storage_data_protector");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

# Start with a GET request to make sure we're looking at the proper service
res = http_send_recv3(
  method:'GET',
  item:'/dpnepolicyservice/DPNECentral.asmx',
  port:port,
  exit_on_fail:1
);
if (isnull(res[2]) || "DPNECentral Web Service" >!< res[2])
  exit(0, "The web server listening on port "+port+" does not appear to be Data Protector DPNECentral Web Service.");

# Send a get_ServerVersion request
postdata =
  '<?xml version="1.0" encoding="utf-8"?>\n' +
  '<soap:Envelope\n' +
  '  xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"\n' +
  '  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n' +
  '  xmlns:xsd="http://www.w3.org/2001/XMLSchema">\n' +
  '  <soap:Body>\n' +
  '    <get_ServerVersion\n' +
  '      xmlns="http://hp.com/"/>\n' +
  '  </soap:Body>\n' +
  '</soap:Envelope>\n';

res = http_send_recv3(
  method:'POST',
  item:'/dpnepolicyservice/DPNECentral.asmx',
  port:port,
  version:11,
  add_headers:make_array(
    'Content-Type', 'text/xml; charset=utf-8',
    'SOAPAction', '"http://hp.com/get_ServerVersion"'
  ),
  data:postdata,
  exit_on_fail:1
);

installs = NULL;
version = NULL;
if (
  'HTTP/1.1 200 OK' >< res[0] &&
  '<soap:Body>' >< res[2] &&
  '<get_ServerVersionResult>' >< res[2]
)
{
  # Extract the version number
  start = stridx(res[2], '<get_ServerVersionResult>') + strlen('<get_ServerVersionResult>');
  end = stridx(res[2], '</get_ServerVersionResult>') - 1;
  if (start >= 0 && end > start)
  {
    version = substr(res[2], start, end);
  }
  installs = add_install(
    installs:installs,
    ver:version,
    dir:'/dpnepolicyservice',
    appname:'dpnepolicyservice',
    port:port
  );
}

if (isnull(installs))
  exit(1, 'Failed to extract the version of HP Data Protector DPNECentral Web Service hosted on the web server listening on port '+port+'.');

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'HP Data Protector DPNECentral Web Service',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
