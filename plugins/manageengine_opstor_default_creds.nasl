#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62783);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/07 18:43:41 $");

  script_name(english:"ManageEngine OpStor Default Administrator Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:
"A web application is protected using default administrative
credentials.");
  script_set_attribute(attribute:"description", value:
"The remote ManageEngine OpStor install uses a default set of
credentials ('admin' / 'admin') to control access to its management
interface.

With this information, an attacker can gain administrative access to
the application.");
  script_set_attribute(attribute:"solution", value:
"Log into the application and change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_opstor");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("manageengine_opstor_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);
  script_require_keys("www/manageengine_opstor");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname      : "manageengine_opstor",
  port         : port,
  exit_on_fail : TRUE
);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install["dir"];
install_loc = build_url(qs:dir, port:port);

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

user = "admin";
pass = "admin";

postdata =
  "userName=" + user + "&" +
  "password=" + pass + "&" +
  "Submit=Log+In";

url = dir +  "/jsp/Login.do";
res = http_send_recv3(
  port            : port,
  method          : "POST",
  item            : url,
  data            : postdata,
  content_type    : "application/x-www-form-urlencoded",
  follow_redirect : 1,
  exit_on_fail    : TRUE
);

if (
  (
    'class="rowcontent"><a href="/logout.do">Logout' >< res[2] &&
    '>Storage Infrastructure<' >< res[2]
  ) ||
  'Welcome to OpStor Wizard</strong>' >< res[2]
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
audit(AUDIT_WEB_APP_NOT_AFFECTED, "ManageEngine OpStor", install_loc);
