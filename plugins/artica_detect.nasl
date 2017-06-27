#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50323);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/09 00:11:21 $");

  script_name(english:"Artica Detection");
  script_summary(english:"Looks for Artica login page");

  script_set_attribute(attribute:"synopsis", value:"A web-based management console is installed on the remote host.");
  script_set_attribute(attribute:"description",value:
"Artica, a web-based management console for Postfix, is installed on
the remote system.");
  script_set_attribute(attribute:"see_also", value:"http://www.artica.fr/index.php/home/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 9000);
  script_require_keys("www/lighttpd");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:9000);
dir = '';
url = "/logon.php";
installs = NULL;

banner = get_http_banner(port:port, exit_on_fail:TRUE);
if (isnull(banner)) exit(1, 'Unable to get the banner from the web server on port '+port+'.');

headers = parse_http_headers(status_line:banner, headers:banner);
if (isnull(headers))
  exit(1, 'Error processing HTTP response headers from the web server on port '+port+'.');

server = headers['server'];
if (isnull(server))
  exit(0, "The web server on port "+port+" doesn't send a Server response header.");

if ('lighttpd' >!< server)
  exit(0, "The web server on port "+port+" doesn't appear to use lighttpd.");


res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (
  '<strong>Artica for postfix'   ><  res[2]  &&
  "Set_Cookie('artica-template'" ><  res[2]  &&
  "Set_Cookie('artica-language"  ><  res[2]  &&
  'href="css/artica-theme'       ><  res[2]
)
{
  ver = UNKNOWN_VER;

  installs = add_install(
    installs:installs,
    dir     : dir,
    appname :'artica',
    ver     : ver,
    port    : port
  );

  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name : 'Artica',
      installs     : installs,
      port         : port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, 'Artica wasn\'t detected on port '+port+'.');
