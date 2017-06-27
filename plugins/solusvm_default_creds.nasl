#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66973);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/09 21:14:09 $");

  script_name(english:"SolusVM Default Administrator Credentials");
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
"The remote SolusVM install uses a default set of credentials
('vpsadmin' / 'vpsadmin') to control access to its management interface. 

With this information, an attacker can gain administrative access to the
application."
  );
  script_set_attribute(attribute:"solution", value:"Log into the application and change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:solusvm:solusvm");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("solusvm_detect.nasl");
  script_require_ports("Services/www", 5353, 5656);
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/solusvm");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:5353);

install = get_install_from_kb(
  appname      : "solusvm",
  port         : port,
  exit_on_fail : TRUE
);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install["dir"];
login_url = "/admincp/login.php";
url = dir + login_url;

install_loc = build_url(qs:url, port:port);

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

user = "vpsadmin";
pass = "vpsadmin";

postdata =
  "username=" + user + "&" +
  "password=" + pass + "&" +
  "Submit=Login";

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
  '>SolusVM Administration<' >< res[2] &&
  'function admin_logout()' >< res[2]
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

    report = get_vuln_report(
      items   : url,
      port    : port,
      header  : header,
      trailer : trailer
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "SolusVM", install_loc);
