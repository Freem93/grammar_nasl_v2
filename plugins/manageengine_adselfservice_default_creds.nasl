#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56510);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_name(english:"ManageEngine ADSelfService Plus Default Administrator Credentials");
  script_summary(english:"Attempts to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote web server is protected using
default administrative credentials.");
  script_set_attribute(attribute:"description", value:
"The instance of ManageEngine ADSelfService Plus running on the remote
web server uses a default set of credentials ('admin' / 'admin') to
control access to its management interface. A remote attacker can
exploit this to gain full administrative access to the application.");
  script_set_attribute(attribute:"solution", value:
"Log into the application and use the 'Personalize' feature to change
the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:zohocorp:manageengine_adselfservice_plus");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_adselfservice_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/ManageEngine ADSelfService Plus");
  script_require_ports("Services/www", 8888);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:8888);

install = get_single_install(app_name:'ManageEngine ADSelfService Plus', port:port);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install['path'];
install_url = build_url(port:port, qs:dir+"/authorization.do");

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

# Try to log in.
user = 'admin';
pass = 'admin';

url = dir + '/authorization.do';
res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE, follow_redirect:1);
if (
  'action="j_security_check?loginComponent=AdminLogin&formSubmit=SSP' >!< res[2] &&
  'src="showLogin.cc?logincomponent=yes"' >!< res[2]
) exit(1, "The ManageEngine ADSelfService Plus install at "+install_url+" has an unexpected form.");

# Make sure we have a session cookie.
val = get_http_cookie(name:"JSESSIONID");
if (isnull(val)) val = get_http_cookie(name:"JSESSIONIDADSSP");
if (isnull(val)) exit(1, "Failed to extract the session cookie from the ManageEngine ADSelfService Plus install at "+install_url+".");

postdata =
  'j_username=' + user + '&' +
  'j_password=' + pass + '&' +
  'domainName=ADSelfService+Plus+Authentication&' +
  'domainName=-&' +
  'AUTHRULE_NAME=ADAuthenticator';

url2 = dir + '/j_security_check?loginComponent=AdminLogin&formSubmit=SSP';
res2 = http_send_recv3(
  port            : port,
  method          : 'POST',
  item            : url2,
  data            : postdata,
  content_type    : "application/x-www-form-urlencoded",
  follow_redirect : 2,
  exit_on_fail    : TRUE
);

if (
  '>Welcome,&nbsp;&nbsp;<b>' + user + '</b>' >< res2[2] ||
  egrep(pattern:">Sign out<", string:res2[2])
)
{
  report =  '\nNessus was able to gain access using the following URL\n' +
            '\n ' + install_url + '\n' +
            '\nand the following set of credentials :\n' +
            '\n' +
            '  Username : ' + user + '\n' +
            '  Password : ' + pass + '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "ManageEngine ADSelfService Plus", install_url);
