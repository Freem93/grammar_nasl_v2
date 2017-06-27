#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42337);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/07 21:18:29 $");

  script_name(english:"OSSIM Web Frontend Default Credentials");
  script_summary(english:"Tries to login as admin/admin");

  script_set_attribute(attribute:"synopsis", value:"The remote web application uses default credentials.");
  script_set_attribute(attribute:"description", value:
"It is possible to log into the remote OSSIM web frontend by providing
the default credentials. A remote attacker could exploit this to gain
administrative control of the OSSIM web frontend.");
  script_set_attribute(attribute:"solution", value:"Secure the admin account with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("ossim_web_detect.nasl");
  script_require_keys("www/ossim", "www/PHP");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'ossim', port:port, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

user = 'admin';
pass = 'admin';
dir = install['dir'];
url = '/session/login.php';
install_url = build_url(port:port, qs:dir);

res = http_send_recv3(method:"GET", item:dir + url, port:port, exit_on_fail:TRUE);

headers = make_array("Content-Type", "application/x-www-form-urlencoded");
postdata = "user=" + user + "&" + "pass=" + pass;
res = http_send_recv3(
  method:"POST",
  item:dir + url,
  port:port,
  add_headers:headers,
  data:postdata,
  exit_on_fail:TRUE
);

hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(hdrs['$code'])) code = 0;
else code = hdrs['$code'];

if (isnull(hdrs['location'])) location = "";
else location = hdrs['location'];

# If the login succeeds, we'll be redirected to the admin console
if (
  code == 302 &&
  "../index.php" >< location
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to gain access using the following information :\n' +
      '\n' +
      '  URL      : ' + install_url + url + '\n' +
      '  User     : ' + user + '\n' +
      '  Password : ' + pass + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "OSSIM", install_url);
