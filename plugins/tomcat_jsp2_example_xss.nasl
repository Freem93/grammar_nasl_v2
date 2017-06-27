#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47708);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_cve_id("CVE-2005-4838");
  script_osvdb_id(12721, 34878, 34879);

  script_name(english:"Apache Tomcat JSP2 Examples XSS");
  script_summary(english:"Checks for XSS in Apache Tomcat JSP examples.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts one or more scripts that are affected by
cross-site scripting vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Apache Tomcat installation is affected by multiple
cross-site scripting vulnerabilities because several of the JSP
example scripts do not properly validate user input."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://tomcat.apache.org/security-4.html#Fixed_in_Apache_Tomcat_4.1.32"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff24a75b"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Apache Tomcat version 4.1.32 / 5.0.HEAD / 5.5.7 or later.
Alternatively, undeploy Apache Tomcat example web applications.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

info = '';
vuln = 0;
port = get_http_port(default:8080);

# Test 1
cgi  = 'textRotate.jspx';
qs   = 'name=NESSUS<script>if(typeof(already_alerted)=="undefined")'
       + '{already_alerted=0;}if(!already_alerted){alert("' 
       + SCRIPT_NAME + '");already_alerted=1;}</script>';
dir  = '/jsp-examples/jsp2/jspx/';

vuln = test_cgi_xss(
  port       : port,
  cgi        : cgi,
  qs         : qs,
  pass_re    : '\\{alert\\("' +SCRIPT_NAME+ '"\\)',
  ctrl_re    : '<text text-anchor="middle" style="font-size:75;font-family:Serif;fill:white">NESSUS<script>',
  dirs       : make_list(dir),
  silent     : 1
);

if (vuln) info = '\n\n  - ' + build_url(port:port, qs:dir + cgi + '?' + qs);

# Test 2 
if (!vuln || thorough_tests)
{
  cgi  = 'implicit-objects.jsp';
  qs   = 'foo=NESSUS<script>alert(\'' + SCRIPT_NAME + '\')</script>';
  dir  = '/jsp-examples/jsp2/el/';

  vuln = test_cgi_xss(
    port       : port,
    cgi        : cgi,
    qs         : qs,
    pass_re    : 'name="foo" value="NESSUS<script>alert\\(\''+SCRIPT_NAME+'\'\\)',
    ctrl_re    : '<form action="implicit-objects.jsp" method="GET">',
    dirs       : make_list(dir),
    silent     : 1
  );
  if (vuln) info += '\n\n  - ' + build_url(port:port, qs:dir + cgi + '?' + qs);
}

# Test 3
if (!vuln || thorough_tests)
{
  cgi = 'functions.jsp';
  qs  = 'foo=NESSUS<script>alert("' + SCRIPT_NAME + '")</script>';
  dir = '/jsp-examples/jsp2/el/';

  vuln = test_cgi_xss(
    port       : port,
    cgi        : cgi,
    qs         : qs,
    pass_re    : 'foo = <input type="text" name="foo" value="NESSUS<script>alert\\("'+SCRIPT_NAME+'"\\)</script>',
    ctrl_re    : '<form action="functions.jsp" method="GET">',
    dirs       : make_list(dir),  
    silent     : 1
  );
  if (vuln) info += '\n\n  - ' + build_url(port:port, qs:dir + cgi + '?' + qs);
}

if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 3) s = "s have been identified to demonstrate the problems";
    else s = " has been identified to demonstrate the problem";

    report = 'The following URL' + s + ' :' + info;
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The Tomcat server listening on port " + port + " is not affected.");
