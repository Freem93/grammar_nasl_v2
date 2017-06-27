#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77709);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_name(english:"IBM Rational License Key Server Administration and Reporting Tool Default Credentials");
  script_summary(english:"Checks for the default login credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application with a default set of
known login credentials.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to login to the remote web interface for the IBM
Rational License Key Server Administration and Reporting Tool using a
default set of known credentials.");
  # http://pic.dhe.ibm.com/infocenter/rational/v0r0m0/topic/com.ibm.rational.license.doc/topics/t_SrvAdmRpt_AddLicServ.html
  # The original link above now gets redirected to the following:
  # http://pic.dhe.ibm.com/infocenter/rational/v0r0m0/index.jsp?topic=/com.ibm.rational.license.doc/topics/t_SrvAdmRpt_AddLicServ.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76a417b4");
  script_set_attribute(attribute:"solution", value:"Change the password for the default login.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_license_key_server");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_rlks_administration_reporting_tool.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/IBM Rational License Key Server Administration and Reporting Tool");
  script_require_ports("Services/www", 4743);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:4743);

app = "IBM Rational License Key Server Administration and Reporting Tool";

get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

init_cookiejar();

version = install['version'];

test_login = '/jts/authenticated/identity?redirectPath=/rcladmin/report/hello';

# initialize the session and get a session cookie which
# is needed prior to making the POST request.
res = http_send_recv3(
   method:'GET',
   item: '/rcladmin/report/hello',
   port:port,
   follow_redirect:2,
   exit_on_fail:TRUE
);

install_url = build_url(port:port, qs:'/rcladmin/Main.jsp');

user = 'rcladmin';
pass = 'rcladmin';

postdata =
  'j_username='+user+
  '&j_password='+pass;

res = http_send_recv3(
   method:'POST',
   item:'/jts/authenticated/j_security_check',
   data:postdata,
   content_type:'application/x-www-form-urlencoded',
   add_headers:make_array('referer', build_url(port:port, qs:test_login)),
   port:port,
   follow_redirect:2,
   exit_on_fail:TRUE
);

if (
  '/rcladmin/report/hello?request_token_secret=' >< res[2] &&
  'http-equiv="refresh"' >< res[2] && 
  'authfailed' >!< res[1]
)
{
  if (report_verbosity > 0)
  {
    report = '\n' + 'Nessus was able to login to the remote web application with the' +
             '\n' + 'following credentials :' +
             '\n' +
             '\n' + '  URL      : ' + install_url +
             '\n' + '  Username : ' + user +
             '\n' + '  Password : ' + pass +
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
