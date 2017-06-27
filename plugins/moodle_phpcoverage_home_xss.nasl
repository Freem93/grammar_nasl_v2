#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51852);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/01/14 03:46:11 $");

  script_bugtraq_id(46085);
  script_osvdb_id(70735);

  script_name(english:"Moodle 'PHPCOVERAGE_HOME' Parameter XSS");
  script_summary(english:"Attempts to inject script code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a
cross-site vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Moodle installed on the remote host does not sanitize
user-supplied input to the 'PHPCOVERAGE_HOME' parameter of the
'lib/spikephpcoverage/src/phpcoverage.remote.top.inc.php' script
before using it to generate dynamic HTML.

An attacker can leverage this issue to inject arbitrary HTML or script
code into a user's browser to be executed within the security context
of the affected site.");
  # http://packetstormsecurity.com/files/98053/Moodle-2.0.1-Cross-Site-Scripting.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c204efe");
  script_set_attribute(attribute:"solution", value:"Upgrade to Moodle 2.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moodle:moodle");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl");
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

# Try to exploit the issue.
alert = '<script>alert("' + SCRIPT_NAME + '")</script>';

vuln = test_cgi_xss(
  port     : port,
  cgi      : '/lib/spikephpcoverage/src/phpcoverage.remote.top.inc.php',
  dirs     : make_list(dir),
  qs       : 'PHPCOVERAGE_HOME='+urlencode(str:alert),
  pass_str : 'Could not locate PHPCOVERAGE_HOME [' + alert + ']',
  pass2_re : 'php <filename> PHPCOVERAGE_HOME=/path/to/coverage/home'
);
if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
