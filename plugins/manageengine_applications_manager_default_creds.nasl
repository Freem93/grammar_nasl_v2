#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63158);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_name(english:"ManageEngine Applications Manager Default Administrator Credentials");
  script_summary(english:"Attempts to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is protected using
default administrative credentials.");
  script_set_attribute(attribute:"description", value:
"The ManageEngine Applications Manager running on the remote host uses
a default set of credentials ('admin' / 'admin') to control access to
its management interface. An attacker can exploit this to gain
administrative access to the application.");
  script_set_attribute(attribute:"see_also", value:"https://www.manageengine.com/products/applications_manager/");
  script_set_attribute(attribute:"solution", value:
"Log into the application and personalize the account to change the
default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:manageengine:applications_manager");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_applications_manager_detect.nasl");
  script_require_keys("installed_sw/ManageEngine Applications Manager");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 9090);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "ManageEngine Applications Manager";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:9090);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

user = 'admin';
pass = 'admin';

# Establish a Session Cookie
url= '/index.do';
res = http_send_recv3(
  method       : "GET",
  item         : url,
  port         : port,
  exit_on_fail : TRUE
);

data =
  "j_username=" + user + "&" +
  "j_password=" + pass + "&" +
  "AUTHRULE_NAME=Authenticator&Submit";

url = '/j_security_check';
res = http_send_recv3(
  method          : "POST",
  item            : url,
  port            : port,
  content_type    : "application/x-www-form-urlencoded",
  follow_redirect : 2,
  data            : data,
  exit_on_fail    : TRUE
);

if (
  ("adminAction.do?" >< res[2]) &&
  ereg(pattern:'<title>Applications Manager\\s+-\\s+Getting Started</title>',string:res[2], multiline:TRUE)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to gain access to the administrative interface using' +
      '\nthe following information :' +
      '\n' +
      '\n  URL      : ' + install_url +
      '\n  Username : ' + user +
      '\n  Password : ' + pass + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
