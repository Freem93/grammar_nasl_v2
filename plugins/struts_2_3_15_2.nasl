#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70168);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/30 19:28:01 $");

  script_cve_id("CVE-2013-4310");
  script_bugtraq_id(62584);
  script_osvdb_id(97543);

  script_name(english:"Apache Struts 2 'action:' Parameter Prefix Security Constraint Bypass");
  script_summary(english:"Tests the handling of an action.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a web application that uses a Java
framework that is affected by a security constraint bypass
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web application appears to use Struts 2, a web framework
used for creating Java web applications. The version of Struts 2 in
use is affected by a security constraint bypass vulnerability due to a
flaw in the action mapping mechanism. Under certain unspecified
conditions, an attacker could exploit this issue to bypass security
constraints. 

Note that this version of Struts 2 is known to have Dynamic Method
Invocation (DMI) enabled by default. This can expose Struts 2 to
additional vulnerabilities so it is recommended that DMI be disabled. 
(CVE-2013-4316)

Note that this plugin will only report the first vulnerable instance
of a Struts 2 application."
  );
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/s2-018.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.3.15.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

port = get_http_port(default:8080);
cgis = get_kb_list('www/' + port + '/cgi');

urls = make_list();
# To identify actions that we can test the exploit on we will look
# for files with the .action / .jsp / .do suffix from the KB.
if (!isnull(cgis))
{
  foreach cgi (cgis)
  {
    match = eregmatch(pattern:"((^.*)(/.+\.act(ion)?)($|\?|;))", string:cgi);
    if (match)
    {
      urls = make_list(urls, match[0]);
      if (!thorough_tests) break;
    }
    match2 = eregmatch(pattern:"(^.*)(/.+\.jsp)$", string:cgi);
    if (!isnull(match2))
    {
      urls = make_list(urls, match2[0]);
      if (!thorough_tests) break;
    }
    match3 = eregmatch(pattern:"(^.*)(/.+\.do)$", string:cgi);
    if (!isnull(match3))
    {
      urls = make_list(urls, match3[0]);
      if (!thorough_tests) break;
    }
  }
}
if (thorough_tests)
{
  cgi2 = get_kb_list('www/' + port + '/content/extensions/act*');
  if (!isnull(cgi2)) urls = make_list(urls, cgi2);

  cgi3 = get_kb_list('www/' + port + '/content/extensions/jsp');
  if (!isnull(cgi3)) urls = make_list(urls, cgi3);

  cgi4 = get_kb_list('www/' + port + '/content/extensions/do');
  if (!isnull(cgi4)) urls = make_list(urls, cgi4);
}

if (max_index(urls) == 0)
  audit(AUDIT_WEB_FILES_NOT, "Struts 2 .action / .do / .jsp", port);

urls = list_uniq(urls);

script = SCRIPT_NAME - ".nasl" + '-' + unixtime();
vuln = FALSE;

foreach url (urls)
{
  vuln_url = url + "?action:" + script;

  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : vuln_url,
    fetch404     : TRUE,
    exit_on_fail : TRUE
  );

  # Verify our 404 page contains our script name and verify that
  # .action was not appended to our script name as this would
  # indicate that 2.3.15.2 or later is in use
  if (
     res[0] =~ "404 Not Found" &&
     res[2] =~ "\<b\>message\</b\> .*/" + script &&
     res[2] !~ "\<b\>message\</b\> .*/" + script + "\.action"
  )
  {
    vuln = TRUE;
    break;
  }
  # Stop after first vulnerable Struts app is found
  if (vuln) break;
}

if (!vuln) exit(0, 'No vulnerable applications were detected on the web server listening on port '+port+'.');

output = strstr(res[2], "message");
if (empty_or_null(output)) output = res[2];

security_report_v4(
  port       : port,
  severity   : SECURITY_WARNING,
  generic    : TRUE,
  request    : make_list(build_url(qs:vuln_url, port:port)),
  output     : chomp(output)
);
