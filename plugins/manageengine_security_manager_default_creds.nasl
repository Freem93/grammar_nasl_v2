#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(63205);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/21 20:57:10 $");

  script_name(english:"ManageEngine Security Manager Plus Default Administrator Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application is protected using default administrative
credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote ManageEngine Security Manager Plus install uses a default
set of credentials ('admin' / 'admin') to control access to its
management interface.

With this information, an attacker could gain administrative access to
the application."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.manageengine.com/products/security-manager/");
  script_set_attribute(
    attribute:"solution",
    value:
"Log into the application and personalize the account to change the
default login credentials."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:zohocorp:manageengine_security_manager_plus");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("manageengine_security_manager_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/manageengine_security_manager");
  script_require_ports("Services/www", 6262);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:6262);
appname = "ManageEngine Security Manager Plus";

user = 'admin';
pass = 'admin';

install = get_install_from_kb(appname:'manageengine_security_manager', port:port, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
dir = install['dir'];
version = install['ver'];

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

# Obtain Session Cookie
url= '/SecurityManager.cc';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

val = get_http_cookie(name:"JSESSIONID");
if (isnull(val)) exit(1, "Failed to extract the session cookie from the ManageEngine Security Manager Plus install at " + build_url(port:port, qs:dir+"/") + ".");

http_set_read_timeout(get_read_timeout() * 2);

url = '/j_security_check';
data = "j_username=" + user + "&j_password=" + pass + "&Submit=";
res = http_send_recv3(
  method:"POST",
  item:url,
  port:port,
  content_type:"application/x-www-form-urlencoded",
  follow_redirect:1,
  data:data,
  exit_on_fail:TRUE
);

# If fails and return to login page and version 5.4
if (
  'document.getElementById("j_username")' >< res[2] &&
  'class="login_admin">First time users use <strong>' >< res[2] &&
  version == '5.4'
)
{
  data = "j_username=" + user + "&" + "j_password=" + pass + "&AUTHRULE_NAME=ADAuthenticator&domainName=LOCAL&Submit=";
  res = http_send_recv3(
    method:"POST",
    item:url,
    port:port,
    content_type:"application/x-www-form-urlencoded",
    follow_redirect:1,
    data:data,
    exit_on_fail:TRUE
  );
}

if (
  "/agent/windows/SecurityManagerPlusAgent.exe" >< res[2] &&
  "Sign Out <strong>[</strong>admin<strong>]</strong>" >< res[2]
)
{
  if (report_verbosity > 0)
  {
    header = 'Nessus was able to gain access using the following URL';
    trailer =
      'and the following set of credentials :\n' +
      '\n' +
      '  Username : ' + user + '\n' +
      '  Password : ' + pass;

    report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(port:port, qs:dir+"/"));

