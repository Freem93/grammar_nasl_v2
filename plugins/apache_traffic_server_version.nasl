#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(58592);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/22 20:50:46 $");

  script_name(english:"Apache Traffic Server Version");
  script_summary(english:"Obtains the version of the remote Apache Traffic Server.");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the version number of the remote Apache
Traffic Server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Apache Traffic Server, an open source
caching server. It was possible to read the version number from the
banner.");
  script_set_attribute(attribute:"see_also", value:"http://trafficserver.apache.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:traffic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/apache_traffic_server");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');

app = 'Apache Traffic Server';
port = get_http_port(default:8080);

# Get the pristine banner
server_header = http_server_header(port:port);
if (isnull(server_header)) audit(AUDIT_WEB_NO_SERVER_HEADER, port);
if ('ATS/' >!< server_header) audit(AUDIT_WRONG_WEB_SERVER, port, app);;

ver = NULL;
ver_pat = '^ATS/([0-9\\.]+)';

match = eregmatch(pattern:ver_pat, string:server_header);
if (match[1]) ver = match[1];

set_kb_item(name:'www/'+port+'/apache_traffic_server', value:TRUE);
set_kb_item(name:'www/'+port+'/apache_traffic_server/source', value:server_header);
if (ver) set_kb_item(name:'www/'+port+'/apache_traffic_server/version', value:ver);

if (report_verbosity > 0)
{
  report =
    '\n  Version source : ' + server_header +
    '\n  Version        : ' + ver + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
