#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77855);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_name(english:"Silver Peak VX Default Credentials");
  script_summary(english:"Attempts to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:"A web application is protected using default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a Silver Peak VX installation that uses
default credentials for the 'admin' account. A remote attacker can
exploit this to gain administrative access to the application.");
  script_set_attribute(attribute:"solution", value:
"Log into the application and change the default password for the
'admin' user.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:silver_peak:vx");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("silver_peak_vx_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/Silver Peak VX");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Silver Peak VX";
get_install_count(app_name:app, exit_if_zero:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:80, php:TRUE, embedded:TRUE);
install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
report_url = build_url(qs:dir, port:port);
url = NULL;

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

# Default Credentials
user = "admin";
pass = "admin";

# Try to log in.
info = "";
postdata = '{"user":"' +user+ '","password":"' +pass+ '"}';

res = http_send_recv3(
  method : "POST",
  port   : port,
  item   : "/rest/json/login",
  content_type : "application/json; charset=UTF-8",
  data   : postdata,
  exit_on_fail : TRUE
);
if (
  "Authentication successful" >< res[2] &&
 "401 Unauthorized" >!< res[0]
)
{
  info +=
    '\n  Username : ' + user +
    '\n  Password : ' + pass + '\n';

  if (report_verbosity > 0)
  {
    report = '\n' + 'Nessus was able to gain access using the following URL :' +
             '\n' +
             '\n' + '  ' + report_url +
             '\n' +
             '\n' + 'and the following set of credentials :\n' +
             info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, report_url);
