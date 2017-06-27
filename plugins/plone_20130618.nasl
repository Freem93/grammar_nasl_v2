#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67205);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");
  
  script_cve_id("CVE-2013-4190");
  script_bugtraq_id(60339, 61953);
  script_osvdb_id(95852);

  script_name(english:"Plone spamProtect mailaddress Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a Python script that is affected by a
cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Plone installed on the remote web server is affected 
by a cross-site scripting vulnerability because it fails to properly
sanitize input to the 'mailaddress' parameter of the 'spamProtect.py'
script.  An attacker may be able to leverage this to inject arbitrary
HTML and script code into a user's browser to be executed within the
security context of the affected site. 

Note that the application is also reportedly affected by several 
additional vulnerabilities. Some of the reported vulnerabilities
include but are not limited to arbitrary code execution, privilege 
escalation, denial of service (DoS), open redirect, cross-site 
scripting, as well as several additional flaws; however, Nessus has 
not tested for the additional issues."
  );
  # https://plone.org/products/plone/security/advisories/20130618-announcement
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05118bde");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2013/q3/258");
  script_set_attribute(attribute:"see_also", value:"http://plone.org/products/plone-hotfix/releases/20130618");
  script_set_attribute(attribute:"solution", value:
"Follow the instructions in the advisory to apply the hotfix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:plone:plone");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("plone_detect.nasl");
  script_require_keys("www/plone");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname : "plone",
  port    : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
xss_test = "><script>alert('" + (SCRIPT_NAME - ".nasl") + "-" + unixtime() +
           "')</script>";

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : '/spamProtect',
  qs       : 'mailaddress=' + urlencode(str:xss_test),
  pass_str : '&#0109;ailto&#0058;' + xss_test,
  pass_re  : "<a href="
);

if (!exploit)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Plone", build_url(qs:dir, port:port));
