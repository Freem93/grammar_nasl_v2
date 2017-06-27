#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61597);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_name(english:"Scrutinizer Default Credentials Check");
  script_summary(english:"Tries to login using default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running a web application with default credentials.");
  script_set_attribute(
    attribute:"description",
    value:
"The Scrutinizer install on the remote host is using default credentials
for the 'admin' user.  Using these credentials, it is possible to login
and gain access to the back end administrative interface."
  );
  script_set_attribute(attribute:"solution", value:"Change passwords for default accounts.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:sonicwall_scrutinizer");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("scrutinizer_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/scrutinizer_netflow_sflow_analyzer");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(appname:'scrutinizer_netflow_sflow_analyzer', port:port, exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install['dir'];
app_url = build_url(qs:dir, port:port);

appname = 'Scrutinizer Netflow & sFlow Analyzer';

function check_login(username, password)
{
  local_var url, res;
  url = dir + '/cgi-bin/login.cgi?name=' + username + '&pwd=' + password;
  res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

  # {"userid":"1","sessionid":"TNsUcVN5MQeRrfFJ"}
  if(res[2] =~ '{"userid":"[0-9]+","sessionid":"[A-Za-z0-9]+"}')
    return TRUE;
  else
    return FALSE;
}

# username/password
creds = make_array(
  'admin', 'admin'
);

report = '';

foreach username (keys(creds))
{
  password = creds[username];
  if(check_login(username:username, password:password))
  {
    report += '\n    Username : ' + username +
              '\n    Password : ' + password + '\n';
  }
}

if(report != '')
{

  if (report_verbosity > 0)
  {
    report =
    '\nNessus was able to login using the following information :\n' +
    '\n  URL         : ' + build_url(qs:dir, port:port) + '\n' +
    '\n  Credentials : \n' + report;

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, app_url);
