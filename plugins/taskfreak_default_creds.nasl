#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46224);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_name(english:"TaskFreak! Default Credentials");
  script_summary(english:"Attempts to log in as Admin without a password");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that uses default
credentials.");
  script_set_attribute(attribute:"description", value:
"The installation of TaskFreak! hosted on the remote web server uses the
default username and password to control access to its administrative
console. 

Knowing these, an attacker can gain control of the affected
application.");
  script_set_attribute(attribute:"solution", value:
"Login via the administrative interface and change the password for the
'Admin' account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("taskfreak_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);
  script_require_keys("www/taskfreak");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'taskfreak', port:port, exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

user = 'admin';
pass = '';
install_url = build_url(port:port, qs:install['dir']);

postdata = 'tznUserTimeZone=-14400&username=admin&password=&login=Login';
req = http_mk_post_req(
  port:port,
  item:install['dir']+'/login.php',
  add_headers:make_array("Content-Type", "application/x-www-form-urlencoded"),
  data:postdata
);
res = http_send_recv_req(port:port, req:req, follow_redirect:1, exit_on_fail:TRUE);

if (
  '<li>Task' >< res[2] &&
  '<a href="logout.php" title="Logout">' >< res[2] &&
  '<a href="http://www.taskfreak.com">TaskFreak! multi user</a>' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to gain access to the administrative interface using' +
      '\nthe following information :' +
      '\n' +
      '\n  URL      : ' + install_url +
      '\n  User     : ' + user +
      '\n  Password : ' + pass + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "TaskFreak", install_url);
