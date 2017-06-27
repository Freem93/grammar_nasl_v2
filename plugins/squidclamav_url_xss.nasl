#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62030);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/15 03:38:17 $");

  script_cve_id("CVE-2012-4667");
  script_bugtraq_id(55293);
  script_osvdb_id(85238);

  script_name(english:"SquidClamav clwarn.cgi url Parameter XSS");
  script_summary(english:"Tries to inject script code via the url parameter");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a CGI script that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of SquidClamav installed on the remote host is affected by
a cross-site scripting vulnerability because it fails to properly
sanitize user-supplied input to the 'url' parameter of the 'clwarn.cgi'
script.  An attacker may leverage this issue to execute arbitrary script
in the browser of an unsuspecting user to be executed within the
security context of the affected site. 

Note that the application is also reportedly affected by cross-site
scripting vulnerabilities with the 'source', 'virus' and 'user'
parameters of the 'clwarn.cgi' script but Nessus has not tested the
additional parameters.");
  # https://github.com/darold/squidclamav/commit/5806d10a31183a0b0d18eccc3a3e04e536e2315b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a9d0663");
  script_set_attribute(attribute:"see_also", value:"http://squidclamav.darold.net/news.html");
  script_set_attribute(attribute:"solution", value:"Update to version 5.8 / 6.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:darold:squidclamav");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("squidclamav_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/squidclamav");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname      : "squidclamav",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
page = '/clwarn.cgi';
xss_test = '<script>alert(' + "'" + SCRIPT_NAME + '-' + unixtime() + "'" + ')</script>';

pass_re = str_replace(string:xss_test, find:"(", replace:"\(");
pass_re = str_replace(string:pass_re, find:")", replace:"\)");

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : page,
  qs       : 'url=' + urlencode(str:xss_test),
  pass_re  : '(#0000FF">|URL )' + pass_re,
  ctrl_re  : '">SquidClamAv'
);

if (!exploit)  audit(AUDIT_WEB_APP_NOT_AFFECTED, "SquidClamav", build_url(qs:dir+page,port:port));
