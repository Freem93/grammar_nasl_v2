#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71886);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/25 13:26:59 $");

  script_osvdb_id(142566);

  script_name(english:"HP Intelligent Management Center Web Administration Interface Default Credentials");
  script_summary(english:"Attempts to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The HP Intelligent Management Center web administration interface
running on the remote host uses a known set of default credentials.");
  script_set_attribute(attribute:"description", value:
"The web administration interface for the HP Intelligent Management
Center (IMC) application running on the remote host uses a known set
of default credentials. A remote attacker can exploit this to gain
administrative access to the web interface.");
  script_set_attribute(attribute:"solution", value:
"Change the default administrative login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:intelligent_management_center");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_imc_web_interface_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 8080);
  script_require_keys("installed_sw/HP Intelligent Management Center Web Interface");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

appname = 'HP Intelligent Management Center Web Interface';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:8080);

install = get_single_install(
  app_name: appname,
  port: port,
  exit_if_unknown_ver:FALSE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

init_cookiejar();

url = '/imc/login.jsf';

# need to make pre-request before login to get cookie info
# and csrf token
res = http_send_recv3(
  port            : port,
  method          : 'GET',
  item            : url,
  exit_on_fail    : TRUE);

# get anticsrf token
item = eregmatch(pattern:'name="javax.faces.ViewState"[^>]*value="([^"]+)"', string:res[2]);
csrf_token = item[1];
if (isnull(csrf_token))
  csrf_token = '!j_id1';

# default admin/admin login POST request
postdata = 'loginForm%3Anavigator=Nessus&' +
           'loginForm%3AloginName=admin&' +
           'loginForm%3Apassword=admin&' +
           'loginForm%3AloginTypeWebOrDesktop=1&' +
           'org.apache.myfaces.trinidad.faces.FORM=loginForm&' +
           'javax.faces.ViewState=' + urlencode(str:csrf_token) + '&' +
           'source=loginForm%3AloginCmd&' +
           'loginForm%3AloginCmd=Login&' +
           'loginForm_SUBMIT=1';

res = http_send_recv3(
  port            : port,
  method          : 'POST',
  item            : url,
  data            : postdata,
  add_headers     : make_array('Referer', build_url(port:port, qs:url)),
  content_type    : "application/x-www-form-urlencoded",
  exit_on_fail    : TRUE);

install_url = build_url(qs:url, port:port);

if ('Operator or password is incorrect.' >!< res[2] &&
  'loginSuccess' >< res[1])
{
  header = 'Nessus was able to gain access using the following URL';
  trailer =
    'and the following set of credentials :\n' +
    '\n' +
    '  Username : admin\n' +
    '  Password : admin';

    report = get_vuln_report(
      items   : url,
      port    : port,
      header  : header,
      trailer : trailer);

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);
