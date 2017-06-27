#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80225);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/08/31 15:08:48 $");

  script_name(english:"Centreon Default Administrator Password");
  script_summary(english:"Attempts to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"A web application is protected using default administrative
credentials.");
  script_set_attribute(attribute:"description", value:
"The remote Centreon install uses a default set of credentials ('admin'
/ 'centreon') to control access to its management interface. An
attacker can leverage this issue to gain administrative access to the
application.");
  script_set_attribute(attribute:"solution", value:"Log into the application and change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centreon:centreon");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:merethis:centreon");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("centreon_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/PHP", "installed_sw/Centreon");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Centreon";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

url = dir + "/index.php";

user = "admin";
pass = "centreon";

clear_cookiejar();
postdata = 'useralias=' +user+ '&password=' +pass+ '&submit=Connect+%3E%3E';

res = http_send_recv3(
  port            : port,
  method          : "POST",
  item            : url,
  data            : postdata,
  content_type    : "application/x-www-form-urlencoded",
  exit_on_fail    : TRUE,
  follow_redirect : 1
);
if (
  ('alt="Logout"' >< res[2]) &&
  (res[2] =~ ';You are(.*)admin</a>')
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to gain access using the following URL :\n' +
      '\n' + '  ' + build_url(port:port, qs:url) +
      '\n' +
      '\n' + 'and the following set of credentials :' +
      '\n' +
      '\n  Username : ' + user +
      '\n  Password : ' + pass + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
