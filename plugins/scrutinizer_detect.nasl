#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58992);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/05/05 01:11:40 $");

  script_name(english:"Scrutinizer NetFlow & sFlow Analyzer Detection");
  script_summary(english:"Checks for Scrutinizer");

  script_set_attribute(attribute:"synopsis", value:
"A web-based network traffic analysis tool was detected on the remote
host.");
  script_set_attribute(attribute:"description", value:
"Scrutinizer NetFlow & sFlow Analyzer, a network traffic analysis
tool, was detected on the remote web server.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce5ffbac");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/04");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

# Make sure the banner looks correct unless we're paranoid.
if (report_paranoia < 2)
{
  server_header = http_server_header(port:port);
  if (isnull(server_header)) audit(AUDIT_WEB_BANNER_NOT, port);
  if ('Apache' >!< server_header || 'Coyote' >< server_header) audit(AUDIT_WRONG_WEB_SERVER, port, 'Apache');
}

# Scrutinizer is always served from /
installs = NULL;
res = http_send_recv3(method:"GET", item:'/', port:port, exit_on_fail:TRUE);
if (
  '<title>Scrutinizer' >< res[2] &&
  (
    ('For the best Scrutinizer experience possible, please address the issues below' >< res[2]) ||
    (
      'Need Support? Call us at' >< res[2] &&
      'Plixer.com</a>' >< res[2]
    )
  )
)
{
  version = NULL;
  if ('<TD id="loginHeaderTD">' >< res[2])
    pat = 'id="loginHeaderTD">Scrutinizer [0-9\\.]+<';
  else
    pat = '<div id=\'testAlertDivTitle\'>Scrutinizer ([0-9\\.]+)<';

  matches = egrep(pattern:pat, string:res[2]);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        version = item[1];
        break;
      }
    }
  }

  installs = add_install(
    installs:installs,
    ver:version,
    dir:'/',
    appname:'scrutinizer_netflow_sflow_analyzer',
    port:port
  );
}

if (isnull(installs)) audit(AUDIT_NOT_DETECT, 'Scrutinizer NetFlow & sFlow Analyzer', port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Scrutinizer NetFlow & sFlow Analyzer',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
