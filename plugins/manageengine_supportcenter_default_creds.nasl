#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55448);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_name(english:"ManageEngine SupportCenter Plus Default Administrator Credentials");
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
"The remote ManageEngine SupportCenter Plus install uses a default set
of credentials ('administrator' / 'administrator') to control access to
its management interface. 

With this information, an attacker can gain administrative access to the
application."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Log into the application, click 'Personalize' followed by 'Change
Password', and change the password."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:manageengine:supportcenter_plus");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_supportcenter_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/manageengine_supportcenter");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:8080);


install = get_install_from_kb(appname:'manageengine_supportcenter', port:port, exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install['dir'];
install_url = build_url(port:port, qs:dir+"/");


# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();


# Try to log in.
user = "administrator";
pass = "administrator";

url = dir + '/';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if ("form action='j_security_check" >!< res[2])
  exit(1, "The ManageEngine SupportCenter Plus install at "+install_url+" has an unexpected form.");

# Make sure we have a session cookie.
val = get_http_cookie(name:"JSESSIONID");
if (isnull(val)) exit(1, "Failed to extract the session cookie from the ManageEngine SupportCenter Plus install at "+install_url+".");

postdata =
  "j_username=" + user + "&" +
  "j_password=" + pass + "&" +
  "loginButton=Login";

url2 = dir + '/j_security_check';
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
  "javascript:NewWindow('/jsp/About.jsp'" >< res2[2] ||
  'input type=\'hidden\' name="loggedUserID"' >< res2[2] ||
  'wsRtPanel.userDetails" class="hide">User Details<' >< res2[2] ||
  egrep(pattern:user+">Log out<", string:res2[2])
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
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "ManageEngine SupportCenter Plus", install_url);
