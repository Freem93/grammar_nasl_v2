#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76258);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/17 21:38:53 $");

  script_name(english:"Cloudera Manager Default Credentials");
  script_summary(english:"Attempts to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"A web application is protected using default credentials.");
  script_set_attribute(attribute:"description", value:
"The Cloudera Manager web application running on the remote web server
uses default credentials for the administrator account. An attacker
can exploit this to gain administrative access to the application.");
  script_set_attribute(attribute:"solution", value:
"Log in and change the password for the 'admin' user.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudera:cloudera_manager");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("cloudera_manager_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/Cloudera Manager");
  script_require_ports("Services/www", 7180, 7183);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Cloudera Manager";

get_install_count(app_name:app, exit_if_zero:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:7183);

install = get_single_install(
  app_name : app,
  port     : port
);

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

# Try to log in.
info = "";
url = '/cmf/login';

res1 = http_send_recv3(
  method : "GET",
  port   : port,
  item   : url,
  exit_on_fail : TRUE
);

user = "admin";
pass = "admin";

postdata = "j_username="+user+"&j_password="+pass+"&submit=";

res = http_send_recv3(
  port     : port,
  method   : "POST",
  item     : "/j_spring_security_check",
  data     : postdata,
  content_type : "application/x-www-form-urlencoded",
  exit_on_fail : TRUE,
  follow_redirect : 3
);
# There's a problem if we've bypassed authentication.
if (
  'id="adminLinks"' >< res[2] &&
  '>Change Password<' >< res[2] &&
  '>Logout<' >< res[2]
)
{
  info +=
    '\n  Username : ' + user +
    '\n  Password : ' + pass + '\n';
}

if (info)
{
  if (report_verbosity > 0)
  {
    report = '\n' + 'Nessus was able to gain access using the following URL :' +
             '\n' + 
             '\n' + '  ' + build_url(port:port, qs:url) + 
             '\n' +
             '\n' + 'and the following set of credentials :\n' +
             info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(port:port, qs:url));
