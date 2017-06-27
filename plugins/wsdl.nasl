#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65126);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/03/09 01:30:50 $");

  script_name(english:"Web Service Description Language File Detected");
  script_summary(english:"Looks for a WSDL");

  script_set_attribute(
    attribute:"synopsis",
    value:"A web service appears to be running on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A Web Service Description Language (WSDL) file was detected on the
remote web server.  A WSDL file is used to specify the functionality
provided by a web service.  This data is commonly used to describe web
services offered via SOAP over HTTP."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.w3.org/TR/wsdl");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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

port = get_http_port(default:80, embedded:TRUE, dont_break:TRUE);
banner = get_http_banner(port:port, broken:TRUE);
if (isnull(banner)) audit(AUDIT_WEB_BANNER_NOT, port);

headers = parse_http_headers(status_line:banner, headers:banner);
status = headers['$code'];

if (status != 500)
{
  # this audit message may not be 100% true but is good enough for the purposes of this plugin
  audit(AUDIT_WRONG_WEB_SERVER, port, 'a web service');
}

url = '/?wsdl';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

headers = parse_http_headers(status_line:res[0], headers:res[1]);
if (
  headers['$code'] != 200 ||
  ('text/xml' >!< headers['content-type'] && tolower(res[2]) !~ "^<\?xml") || # some pages say they're html even though they're xml
  'wsdl' >!< tolower(res[2]) ||
  ('<service' >!< res[2] && res[2] !~ '=[\'"]http://schemas.xmlsoap.org/wsdl/[\'"]')
)
{
  audit(AUDIT_NOT_DETECT, 'A web service', port);
}

# try to determine what the web service is, if it may be of interest to other plugins
if ('xmlns:IDSP="http://ns.adobe.com/InDesign/soap/"' >< res[2] && 'RunScript' >< res[2])
  set_kb_item(name:'wsdl/adobe_indesign', value:port);

if (report_verbosity > 0)
{
  report = get_vuln_report(port:port, items:url);
  security_note(port:port, extra:report);
}
else security_note(port);
