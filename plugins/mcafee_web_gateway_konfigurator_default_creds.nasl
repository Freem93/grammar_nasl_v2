#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72622);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_name(english:"McAfee Web Gateway User Interface Default Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web service is protected using a default set of known
credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote McAfee Web Gateway user interface uses a known set of
default credentials.  Knowing these, an attacker with access to service
can gain administrative access to the device."
  );
  script_set_attribute(attribute:"solution", value:"Change the default admin login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:mcafee:web_gateway");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_web_gateway_konfigurator_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/mwg_ui");
  script_require_ports("Services/www", 4711);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:4711);

install = get_install_from_kb(appname:"mwg_ui", port:port, exit_on_fail:TRUE);
dir = install['dir'];
install_url = build_url(port:port, qs:dir+"/");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


appname = "McAfee Web Gateway User Interface";
user = 'admin';
pass = 'webgateway';


init_cookiejar();

url = dir + '/Konfigurator/request';

# nb: the device seems to go through an initialization when first contacted.
postdata = 'js=true';

res = http_send_recv3(
  port            : port,
  method          : 'POST',
  item            : url,
  data            : postdata,
  add_headers     : make_array('Referer', install_url+(url - '/')),
  content_type    : "application/x-www-form-urlencoded",
  exit_on_fail    : TRUE
);

for (i=0; " 503 "><res[0] && i<5; i++)
{
  sleep(1);

  res = http_send_recv3(
    port            : port,
    method          : 'POST',
    item            : url,
    data            : postdata,
    add_headers     : make_array('Referer', install_url+(url - '/')),
    content_type    : "application/x-www-form-urlencoded",
    exit_on_fail    : TRUE
  );
}
if (" 503 " >< res[0]) exit(1, "The web server listening on port "+port+" is not available.\n");
if (" 200 " >< res[0]) exit(0, "The web server listening on port "+port+" does not prompt for credentials.\n");
if (" 401 " >!< res[0]) exit(1, "The web server listening on port "+port+" does not report that authentication is required.\n");

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (
  " 200 " >!< res[0] ||
  "Web Gateway - Login" >!< res[2] ||
  'name="userName"' >!< res[2]
) exit(1, "Failed to reach the login form for McAfee Email Gateway UI on port "+port+".");

# Try the login.
postdata = 'userName=' + user + '&' +
           'pass=' + urlencode(str:pass) + '&' +
           'submit=Login' + '&' +
           'f=APPLET';

res = http_send_recv3(
  port            : port,
  method          : 'POST',
  item            : url,
  data            : postdata,
  add_headers     : make_array('Referer', install_url+(url - '/')),
  content_type    : "application/x-www-form-urlencoded",
  follow_redirect : 2,
  exit_on_fail    : TRUE
);
if (
  " 200 " >< res[0] &&
  "f=CLIENT_HEART_BEAT" >< res[2] &&
  "archive='jar/applet.jar" >< res[2] &&
  "<PARAM name='sessionid' value='" >< res[2]
)
{
  if (report_verbosity > 0)
  {
    header = 'Nessus was able to gain access using the following URL';
    trailer =
      'and the following set of credentials :' +
      '\n' +
      '\n' + '  User name : ' + user +
      '\n' + '  Password  : ' + pass;

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
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);
