#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58950);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2011-4237");
  script_bugtraq_id(53439);
  script_osvdb_id(81763);
  script_xref(name:"TRA", value:"TRA-2012-19");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtt34638");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtu18693");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx59431");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx59438");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx59447");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx59451");

  script_name(english:"CiscoWorks Common Services HTTP Response Splitting");
  script_summary(english:"Attempts response splitting attack");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The network management framework on the remote web server has an HTTP
response splitting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of CiscoWorks Common Services on the remote host has an
HTTP response splitting vulnerability.  Common Services is a framework
included with several Cisco products.  Input to the 'URL' parameter of
Autologin.jsp is not properly sanitized. 

A remote attacker could exploit this by tricking a user into making a
malicious request, resulting in the injection of HTTP headers,
modification of the HTTP response body, or splitting the HTTP response
into multiple responses."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2012-19");
  # http://tools.cisco.com/Support/BugToolKit/search/getBugDetails.do?method=fetchBugDetails&bugId=CSCtt34638
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a4f1b73");
  # http://tools.cisco.com/Support/BugToolKit/search/getBugDetails.do?method=fetchBugDetails&bugId=CSCtu18693
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4da1bafd");
  # http://tools.cisco.com/Support/BugToolKit/search/getBugDetails.do?method=fetchBugDetails&bugId=CSCtx59431
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46462822");
  # http://tools.cisco.com/Support/BugToolKit/search/getBugDetails.do?method=fetchBugDetails&bugId=CSCtx59438
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3749073d");
  # http://tools.cisco.com/Support/BugToolKit/search/getBugDetails.do?method=fetchBugDetails&bugId=CSCtx59447
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af05872e");
  # http://tools.cisco.com/Support/BugToolKit/search/getBugDetails.do?method=fetchBugDetails&bugId=CSCtx59451
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d0fd883");
  script_set_attribute(
    attribute:"solution",
    value:"Refer to the referenced Cisco Bug IDs for more information."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/19");   # ?
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/19");  # CPUOM 8.7 released
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:ciscoworks_common_services");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:443);

# the vulnerable page should be at the same location regardless of which product it's being used in
page = '/CSCOnm/servlet/AutoLogin.jsp';
header_name = 'X-' + str_replace(string:SCRIPT_NAME, find:'.', replace:'-');
time = unixtime();
payload = strcat('http://www.example.com/%0d%0a', header_name, ':%20', time);
url = page + '?URL=' + payload;

res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);
headers = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(headers))
  audit(AUDIT_RESP_BAD, port);  # unable to parse headers (not received?) 

# Extract the HTTP header we attempted to inject
header_val = headers[tolower(header_name)];
if (isnull(header_val))
  audit(AUDIT_LISTEN_NOT_VULN, 'CiscoWorks', port);

if (header_val == time)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

  if (report_verbosity > 0)
  {
    trailer =
      'Which injected a "' + header_name + '" header\n' +
      'in the following response :\n\n' + res[0] + chomp(res[1]);
    report = get_vuln_report(items:url, port:port, trailer:trailer);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else
  audit(AUDIT_RESP_BAD, port); # we got back our injected header with an unexpected value

