#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50688);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_cve_id("CVE-2002-2007");
  script_bugtraq_id(4877, 4878);
  script_osvdb_id(13304, 14580);

  script_name(english:"Apache Tomcat Examples Web Root Path Disclosure");
  script_summary(english:"Checks Apache Tomcat Information Disclosure.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Apache Tomcat server is affected by an information
disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The instance of Apache Tomcat listening on the remote host is affected
by an information disclosure vulnerability. An attacker is able to
determine the Tomcat application's web root path by requesting any one
of numerous example files."
  );
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-3.html#Fixed_in_Apache_Tomcat_3.3a");
  script_set_attribute(attribute:"solution", value:"Upgrade to 3.3a or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("http.inc");

port      = get_http_port(default:8080);
vuln_urls = make_list();
test_urls = make_list(
    'test/jsp/pageInfo.jsp',
    'test/jsp/pageImport2.jsp',
    'test/jsp/buffer1.jsp',
    'test/jsp/buffer2.jsp',
    'test/jsp/buffer3.jsp',
    'test/jsp/buffer4.jsp',
    'test/jsp/comments.jsp',
    'test/jsp/extends1.jsp',
    'test/jsp/extends2.jsp',
    'test/jsp/pageAutoFlush.jsp',
    'test/jsp/pageDouble.jsp',
    'test/jsp/pageExtends.jsp',
    'test/jsp/pageImport2.jsp',
    'test/jsp/pageInfo.jsp',
    'test/jsp/pageInvalid.jsp',
    'test/jsp/pageIsErrorPage.jsp',
    'test/jsp/pageIsThreadSafe.jsp',
    'test/jsp/pageLanguage.jsp',
    'test/jsp/pageSession.jsp',
    'test/jsp/declaration/IntegerOverflow.jsp',
    'test/realPath.jsp'
);

get_kb_item_or_exit("tomcat/"+port+"/error_version");
vuln_pat1 = "(\n|The real path is )([A-Z]:\\.*|\/.*)([\/\\]work[\/\\]localhost_8080|[\/\\]webapps[\/\\]test[\/\\]test[\/\\]realPath.jsp)";
vuln_pat2 = "(\n)<h2>Location:.*</h2><b>Internal Servlet Error:</b><br><pre>org\.apache\.jasper\.compiler\.CompileException: ([A-Z]:\\.*|\/.*)webapps[\/\\]test[\/\\].*\.jsp\([0-9],[0-9]\)";

foreach url (test_urls)
{
  r = http_send_recv3(
    port         : port,
    method       : 'GET',
    item         : '/'+url,
    fetch404     : TRUE,
    exit_on_fail : TRUE
  );

  matches = eregmatch(pattern:vuln_pat1, string:r[2]);
  if (!matches)
    matches = eregmatch(pattern:vuln_pat2, string:r[2]);

  if (!isnull(matches[2]))
  {
    vuln_urls = make_list(vuln_urls, url);
    web_root  = matches[2];
  }

  if (!thorough_tests)
    break;
}

if (max_index(vuln_urls) > 0)
{
  if (report_verbosity > 0)
  {
    header = "Nessus was able to obtain the remote Tomcat web root path : " +
      '\n\n' +
      web_root +
      '\n\n' +
      'The install path was obtained using the following URL';
    report = get_vuln_report(port:port, items:vuln_urls, header:header);
    security_warning(port:port, extra:report);
  }
  else
    security_warning(port);
}
else exit(0, "The Tomcat server listening on port " + port + " is not affected.");

