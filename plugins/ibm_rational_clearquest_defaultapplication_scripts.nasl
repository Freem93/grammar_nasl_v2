#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62738);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/10/30 10:47:01 $");

  script_cve_id("CVE-2012-0744");
  script_bugtraq_id(55125);
  script_osvdb_id(84917);

  script_name(english:"IBM Rational ClearQuest Multiple Script Information Disclosure");
  script_summary(english:"Checks for default application template scripts");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple information disclosure
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote install of IBM WebSphere Application Server contains one or
more testing and debugging scripts as well as sample applications,
likely resulting from a deployment of IBM Rational ClearQuest.  These
scripts provide information such as system paths and versions, which may
aid an attacker targeting the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21606317");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21599361");
  script_set_attribute(attribute:"solution", value:"Apply one of the workarounds suggested in the referenced URLs.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ibm:rational_clearquest");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/WebSphere");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# make sure header looks like WebSphere Application Server
server_header = http_server_header(port:port);
if (isnull(server_header)) exit(0, "The web server listening on port " + port + " does not send a Server response header.");
if ("WebSphere Application Server" >!< server_header) audit(AUDIT_WRONG_WEB_SERVER, port, "IBM WebSphere Application Server");

if (thorough_tests) dirs = list_uniq(make_list("/inaccessible", "/unplugged", "/un1qu3_p4th", cgi_dirs()));
else dirs = make_list(cgi_dirs());

file_pats = make_array();
file_pats['/snoop'] = "<h1>Snoop Servlet";
file_pats['/hello'] = "<B>Hello from the WebSphere Application Server!";
file_pats['/ivt'] = "<H1>IVT Servlet";
file_pats['/hitcount'] = "<H1>Hit Count Demonstration";
file_pats['/HitCount.jsp'] = "<H1>Hit Count Demonstration";
file_pats['/HelloHTMLError.jsp'] = "<B>An unexpected error has occurred processing the Hello servlet";
file_pats['/HelloHTML.jsp'] = "<B>Hello from the WebSphere Application Server!";
file_pats['/HelloVXMLError.jsp'] = "An unexpected error has occurred processing the Hello servlet";
file_pats['/HelloVXML.jsp'] = "Hello from the WebSphere Application Server.";
file_pats['/HelloWMLError.jsp'] = "<p>See the WebSphere Application Server log files for error information";
file_pats['/HelloWML.jsp'] = "<p>Hello from the WebSphere Application Server!</p>";
file_pats['/cqweb/j_security_check'] = 'action="j_security_check';

count = 0;
file_found = "";

foreach dir (dirs)
{
  foreach file (sort(keys(file_pats)))
  {
    url = dir + file;
    res = http_send_recv3(
      method       : "GET",
      item         : url,
      port         : port,
      exit_on_fail : TRUE
    );

    if (file_pats[file] >< res[2])
    {
      count++;
      file_found += build_url(port:port, qs:url) + '\n';
    }
  }
}

if (count == 0) audit(AUDIT_LISTEN_NOT_VULN, "IBM WebSphere Application Server", port);


output = ereg_replace(pattern:"//", replace:"/", string:file_found);
report = NULL;

if (report_verbosity > 0)
{
  if (count > 1) script = "scripts";
  else script = "script";

  report =
    '\n' + 'Nessus found the following ' + script + ' included with the' +
    '\n' + 'DefaultApplication template from the WebSphere Application Server' +
    '\n' + 'profile for IBM Rational ClearQuest : ' +
    '\n' +
    '\n' + output +
    '\n';

  security_warning(port:port, extra:report);
  exit(0);
}
else security_warning(port);
