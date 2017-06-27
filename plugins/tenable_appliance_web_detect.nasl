#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58231);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/21 20:57:10 $");

  script_name(english:"Tenable Appliance Web Detection");
  script_summary(english:"Looks for the Tenable Appliance web interface.");

  script_set_attribute(attribute:"synopsis", value:
"The web interface for a security appliance was detected on the remote
host.");
  script_set_attribute(attribute:"description", value:
"The web interface for a Tenable Appliance was detected on the remote
host. A Tenable Appliance can be used to host SecurityCenter, Nessus,
LCE, and PVS.");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/blog/tenable-virtual-appliance");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 8000);
  script_dependencies("http_version.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

app_name = "Tenable Appliance";
port = get_http_port(default:8000);

server_name = http_server_header(port:port);
if ('lighttpd' >!< server_name)
  audit(AUDIT_WEB_BANNER_NOT, 'lighttpd');

# the locale is in the URL of the login page, so rather than guess it we'll
# request the root dir and assume we'll get redirected
dir = '';
url = dir + '/index.html';

res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);

if ('<title>Tenable Appliance</title>' >!< res)
  audit(AUDIT_WEB_FILES_NOT, app_name, port);

install = add_install(
  appname:'tenable_appliance',
  dir:dir,
  port:port
);

request_url = build_url(port:port, qs:url);

report = NULL;
if (report_verbosity > 0)
{
  report = 
  '\n  The following web interface for a Tenable Appliance was detected on the remote host : ' +
  '\n' +
  '\n  ' + request_url +
  '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
