#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65893);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_name(english:"IBM InfoSphere Data Replication Dashboard Default Credentials");
  script_summary(english:"Tries to login using default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application hosted on the remote web server is using default
credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of IBM InfoSphere Data Replication Dashboard on the remote
web server is secured using default credentials (dashboarduser /
dashboarduser).  A remote attacker could exploit this to gain
administrative access to the application."
  );
  script_set_attribute(attribute:"solution", value:"Secure the 'dashboarduser' account with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:infosphere_replication_server");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_qrepldash_detect.nasl");
  script_require_keys("www/ibm_infosphere_data_replication_dashboard");
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
install = get_install_from_kb(appname:'ibm_infosphere_data_replication_dashboard', port:port, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

url = install['dir'] + '/login.do';
user = 'dashboarduser';
pass = 'dashboarduser';
data =
  'j_username=' + user +
 '&j_password=' + hexstr(SHA256(pass));

res = http_send_recv3(
  method:'POST',
  item:url,
  port:port,
  data:data,
  content_type:'application/x-www-form-urlencoded',
  exit_on_fail:TRUE
);

if (res[2] =~ '^<sess userData="false"')
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'IBM InfoSphere Data Replication Dashboard', build_url(qs:install['dir'], port:port));
if (res[2] !~ '^<sess userData="true"')
  audit(AUDIT_RESP_BAD, port, 'login request');

# cleanup
http_send_recv3(method:'GET', item:install['dir'] + '/logout.do', port:port);

if (report_verbosity > 0)
{
  report =
    '\nNessus logged into the web application using the following information :' +
    '\n' +
    '\n  URL      : ' + build_url(qs:install['dir'], port:port) +
    '\n  Username : ' + user +
    '\n  Password : ' + pass + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
