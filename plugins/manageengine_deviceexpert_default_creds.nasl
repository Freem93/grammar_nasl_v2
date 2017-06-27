#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58427);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_name(english:"ManageEngine DeviceExpert Default Administrator Credentials");
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
"The remote ManageEngine DeviceExpert install uses a default set of
credentials ('admin' / 'admin') to control access to its management
interface.

With this information, an attacker can gain administrative access to the
application."
  );
  script_set_attribute(attribute:"solution", value:
"Log into the application and change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:manageengine:device_expert");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_deviceexpert_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 6060);
  script_require_keys("www/manageengine_deviceexpert");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:6060);

install = get_install_from_kb(appname:'manageengine_deviceexpert', port:port, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install['dir'];
install_url = build_url(port:port, qs:dir+"/");

url = dir + '/NCMContainer.cc';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if ("action='/j_security_check" >!< res[2])
  exit(1, "The ManageEngine DeviceExpert install at "+install_url+" has an unexpected form.");

# Make sure we have a session cookie.
val = get_http_cookie(name:"JSESSIONID");
if (isnull(val)) exit(1, "Failed to extract the session cookie from the ManageEngine DeviceExpert install at "+install_url+".");

user = 'admin';
pass = 'admin';

postdata =
  'username=' + user + ' &' +
  'j_username=' + user + '&' +
  'j_password=' + pass + '&' +
  'AUTHRULE_NAME=Authenticator';

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

if("Logout<strong>[</strong>admin<strong>]" >< res2[2] &&
   "<title>DeviceExpert</title>" >< res2[2])
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
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'ManageEngine DeviceExpert', install_url);
