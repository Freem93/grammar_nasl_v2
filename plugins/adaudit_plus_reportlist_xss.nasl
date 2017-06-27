#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(46790);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/04 14:21:27 $");

  script_cve_id("CVE-2010-2049");
  script_bugtraq_id(40253);
  script_osvdb_id(64726);
  script_xref(name:"Secunia", value:"39876");

  script_name(english:"ManageEngine ADAudit Plus 'reportList' Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS");

  script_set_attribute(attribute:"synopsis",value:
"A web application on the remote host has a cross-site scripting
vulnerability."
  );
  script_set_attribute(attribute:"description",value:
"The version of ADAudit Plus installed on the remote web server has a
cross-site scripting vulnerability.  Input passed to the 'reportList'
parameter of 'jsp/audit/reports/ExportReport.jsp' is not properly
sanitized before it is used to generate dynamic HTML content.

An unauthenticated, remote attacker may be able to leverage this issue
to inject arbitrary HTML or script code into a user's browser to be
executed within the security context of the affected site.");

  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("adaudit_plus_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/adaudit_plus");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:8080);
install = get_install_from_kb(appname:'adaudit_plus', port:port, exit_on_fail:TRUE);

dir = install['dir']+'/jsp/audit/reports/';
cgi = 'ExportReport.jsp';
xss = '"</iframe><script>alert('+"'"+SCRIPT_NAME+'-'+unixtime()+"'"+')</script>';

expected_output = 'reportList='+xss;

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:cgi,
  qs:'reportList='+xss,
  pass_str:expected_output,
  ctrl_re:'<title>Export Report *</title>'
);

if (!exploited)
  exit(0, build_url(qs:dir+cgi, port:port) + " is not affected.");
