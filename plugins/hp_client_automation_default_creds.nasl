#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(52979);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/18 20:40:52 $");

  script_name(english:"HP Client Automation Default Credentials");
  script_summary(english:"Attempts to log in with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a web application that uses default
login credentials.");
  script_set_attribute(attribute:"description", value:
"The remote install of HP Client Automation has a default password
('secret') set.  An attacker may connect to it to reconfigure the
application and control remote devices.");
  script_set_attribute(attribute:"solution", value:"Set a strong password for the 'admin' account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:client_automation_administrator");  
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencies("hp_client_automation_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/hp_client_automation");
  script_require_ports("Services/www", 3466);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:3466);

install = get_install_from_kb(appname:'hp_client_automation', port:port, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
install_url = build_url(qs:install['dir'], port:port);

login = 'admin';
pass = 'secret';

url = '/sessionmanager/logon';

postdata = 'username='+login+'&password='+pass+'&directory=';
req = http_mk_post_req(
  port:port,
  item:url,
  add_headers:make_array('Content-Type', 'application/x-www-form-urlencoded'),
  data:postdata
);
res = http_send_recv_req(port:port, req:req, exit_on_fail:TRUE);

if (
  '<sessionmanager>' >< res[2] &&
  '<status>' >< res[2] &&
  'success' >< res[2] &&
  'Logon successful' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to gain access to the administrative interface using' +
      '\n' + 'the following URL :' +
      '\n' +
      '\n  URL      : ' + install_url + url +
      '\n  User     : ' + user +
      '\n  Password : ' + pass + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "HP Client Automation", install_url);
