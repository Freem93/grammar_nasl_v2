#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73300);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_name(english:"Cisco Email Security Appliance Web UI Default Credentials");
  script_summary(english:"Attempts to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web application can be accessed with default credentials.");
  script_set_attribute(attribute:"description", value:
"It is possible to log into Cisco Email Security Appliance's web
management console using default credentials.");
  # http://www.cisco.com/en/US/docs/security/esa/esa7.5/ESA_7.5_CLI_Reference_Guide.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d3f2457");
  script_set_attribute(attribute:"solution", value:
"Refer to the documentation for instructions about changing the default
password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:email_security_appliance");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_esa_web_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);

app_name = "Cisco Email Security Appliance Web UI";
install = get_install_from_kb(appname:"cisco_esa", port:port, exit_on_fail:FALSE);

if (isnull(install)) audit(AUDIT_NOT_INST, app_name);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

url = install['dir'] + '/login';
full_url = build_url(qs:url, port:port);

user = 'admin';
pass = 'ironport';

postdata =
  'action=Login'+
  '&screen=login'+
  '&username='+user+
  '&password='+pass;

res = http_send_recv3(
  method:'POST',
  item:url,
  port:port,
  content_type:'application/x-www-form-urlencoded',
  data:postdata,
  follow_redirect:0,
  exit_on_fail:TRUE
);

# Look at the redirect to determine whether we're being sent back to
# login page (bad creds) or admin console (good creds.)
if ("/login?CSRFKey=" >< res[1] || "/monitor/user_report" >!< res[1])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, full_url);

if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus was able to log into the ' + app_name + ' using' +
    '\n' + 'the following information :' +
    '\n' +
    '\n  URL      : ' + full_url +
    '\n  Username : ' + user +
    '\n  Password : ' + pass + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
