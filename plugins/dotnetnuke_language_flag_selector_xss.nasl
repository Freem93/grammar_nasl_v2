#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66527);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/20 19:40:17 $");

  script_bugtraq_id(58903);
  script_osvdb_id(92036);

  script_name(english:"DNN (DotNetNuke) Language Flag Selector Culture XSS");
  script_summary(english:"Attempts a non-persistent XSS attack.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP.NET application that is affected
by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of DNN installed on the remote host is affected by a
cross-site scripting vulnerability due to the application failing to
properly sanitize user-supplied input when multiple languages are
selected in the flag selector. An unauthenticated, remote attacker can
exploit this, via a specially crafted request, to execute arbitrary
script code in a user's browser session.

Note that this issue is mitigated by requiring that more than one
language be enabled and that the site must use the core language skin
object.

Note also that the application is reportedly affected by an
open-redirection vulnerability, although Nessus has not tested for
this issue.");
  # https://web.archive.org/web/20130421084007/http://www.dotnetnuke.com/News/Security-bulletin-no.78.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1cf7f79");
  script_set_attribute(attribute:"see_also", value:"http://www.dnnsoftware.com/platform/manage/security-center");
  script_set_attribute(attribute:"solution", value:"Upgrade to DNN version 6.2.7 / 7.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("dotnetnuke_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/DNN");
  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");
include("http.inc");
include("install_func.inc");

app = "DNN";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, asp:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);

script = SCRIPT_NAME - ".nasl" + "-" + unixtime();
xss = "<meta><input%20value='" + script + "%27";

expected_output = '\\?\\\\"' + "\<meta\>\<input value=('|%27)" + script +
                  "('|%27)";

exploited = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : '/?\\"' + xss,
  pass_re  : expected_output,
  pass_str : 'Language selected"',
  no_qm    : TRUE
);

if (!exploited)
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
}
