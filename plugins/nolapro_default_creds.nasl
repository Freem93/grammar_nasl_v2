#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46704);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_name(english:"NolaPro Default Credentials");
  script_summary(english:"Attempts to log in with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a web application that uses default
login credentials.");
  script_set_attribute(attribute:"description", value:
"The installation of NolaPro on the remote web server uses the default
username and password to control access to its administrative console. 

Knowing these, an attacker can gain administrative control of the
affected application.");
  script_set_attribute(attribute:"solution", value:
"Log in via the administrative interface and change the password for the
'admin' account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("nolapro_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 50080);
  script_require_keys("www/PHP", "www/nolapro");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:50080, php:TRUE);

install = get_install_from_kb(appname:'nolapro', port:port, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

user = 'admin';
pass = 'pass';
install_url = build_url(port:port, qs:install['dir']);

postdata = 'entered_login='+user+'&entered_password='+pass+'&Submit=Submit';
req = http_mk_post_req(
  port:port,
  item:install['dir']+'/index.php',
  add_headers:make_array("Content-Type", "application/x-www-form-urlencoded"),
  data:postdata
);

res = http_send_recv_req(port:port, req:req, exit_on_fail:TRUE);
if ('<meta http-equiv="refresh" content="0;url=index.php">' >< res[2])
{
  res = http_send_recv3(method:"GET", item:"/index.php", port:port, exit_on_fail:TRUE);
  if (
    '<title>NolaPro Business Management' >< res[2] ||
    'orders">Orders' >< res[2] ||
    'billing">Billing' >< res[2]
  )
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' +
        'Nessus was able to gain access to the administrative interface using\n' +
        'the following information \n' +
        '\n' +
        '  URL      : ' + install_url + '\n' +
        '  User     : ' + user + '\n' +
        '  Password : ' + pass + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "NolaPro", install_url);
