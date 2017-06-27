#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55831);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/11 13:32:17 $");

  script_cve_id("CVE-2011-2410");
  script_bugtraq_id(49184);
  script_osvdb_id(74669);
  script_xref(name:"TRA", value:"TRA-2011-06");

  script_name(english:"HP OpenView Performance Insight sendEmail.jsp XSS");
  script_summary(english:"Attempts reflected XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application running on the remote host has a cross-site
scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of HP OpenView Performance Insight running on the remote
host has a reflected cross-site scripting vulnerability.  Input to the
'bgcolor' parameter of sendEmail.jsp is not properly sanitized.  A
remote attacker could exploit this by tricking a user into requesting
a maliciously crafted URL, resulting in arbitrary script code
execution.

This software has several other cross-site scripting vulnerabilities
and an arbitrary code execution vulnerability, though Nessus has not
checked for those issues."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2011-06");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e8efa18");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the HP OpenView Performance Insight hotfix referenced in the
vendor's advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:openview_performance_insight");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_openview_perf_insight_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/hp_ovpi");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80);
install = get_install_from_kb(appname:'hp_ovpi', port:port, exit_on_fail:TRUE);

dir = install['dir'] + '/jsp';
cgi = '/sendEmail.jsp';
xss = '"><script>alert(/' + SCRIPT_NAME + '/)</script>';
encoded_xss = urlencode(str:xss);
qs = 'url=null&bgcolor=' + encoded_xss;
expected_output = '<body bgcolor="' + xss + '">';

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:cgi,
  qs:qs,
  pass_str:expected_output,
  ctrl_re:"'To' field is required"
);

if (!exploited)
  exit(0, build_url(qs:dir+cgi, port:port) + " is not affected.");
