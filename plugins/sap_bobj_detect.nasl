#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44341);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/09 00:11:24 $");

  script_name(english:"SAP BusinessObjects Detection");
  script_summary(english:"Looks for the CMC login page");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a business intelligence system written
in Java."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running SAP BusinessObjects, a business
intelligence system written in Java."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.sap.com/solutions/sapbusinessobjects/index.epx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:businessobjects");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

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


port = get_http_port(default:6405);

# Make sure the web server looks like Tomcat, which is used to serve the app
banner = get_http_banner(port:port);
if (isnull(banner))
  exit(1, 'Unable to get banner from the web server on port '+port+'.');

headers = parse_http_headers(status_line:banner, headers:banner);
if (isnull(headers))
  exit(1, 'Error processing HTTP response headers from the web server on port '+port+'.');

server = headers['server'];
if (isnull(server))
  exit(0, "The web server on port "+port+" doesn't send a Server response header.");

if ('Apache-Coyote' >!< server)
  exit(0, "The web server on port "+port+" doesn't appear to be Tomcat.");

# This is the default location of the CMC login page, which isn't configurable
url = '/CmcApp/logon.faces';
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if ('<title>BusinessObjects Central Management Console</title>' >< res[2])
{
  installs = add_install(
    installs:installs,
    dir:'/',
    appname:'sap_bobj',
    port:port
  );

  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:'BusinessObjects',
      installs:installs,
      item:url,
      port:port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, "SAP BusinessObjects wasn't detected on port "+port+".");
