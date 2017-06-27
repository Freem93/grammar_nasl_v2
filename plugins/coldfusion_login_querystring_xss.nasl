#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51955);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/23 21:23:02 $");

  script_cve_id("CVE-2011-0580");
  script_bugtraq_id(46273);
  script_osvdb_id(70899, 127832);

  script_name(english:"Adobe ColdFusion login.cfm Query String XSS (APSB11-04)");
  script_summary(english:"Attempts a non-persistent xss.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has is affected by a cross-site
scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote host has is
affected by a cross-site scripting vulnerability in the administrative
web interface. Input to the query string of 'administrator/login.cfm'
is not properly sanitized before being returned in an HTML response.

A remote attacker can exploit this by tricking a user into making a
specially crafted request, resulting in the execution of arbitrary
script code.

This version of ColdFusion likely has several other vulnerabilities,
although Nessus has not checked for those issues.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-04.html");
  # https://helpx.adobe.com/coldfusion/kb/security-hotfix-coldfusion-8-8.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9dd494b2");
  script_set_attribute(attribute:"solution", value:"Apply the hotfix referenced in Adobe's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_detect.nasl");
  script_require_ports("Services/www", 80, 8500);
  script_require_keys("installed_sw/ColdFusion");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'ColdFusion';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

cgi = '/administrator/login.cfm';
xss = '"><img/src="' +unixtime()+ '"/onerror="javascript:alert(/' +SCRIPT_NAME+ '/)">';
expected_output = 'value="' + dir + cgi + '?' + xss;

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:cgi,
  qs:xss,
  pass_str:expected_output,
  ctrl_re:'<title>ColdFusion Administrator Login</title>'
);

if (!exploited)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
