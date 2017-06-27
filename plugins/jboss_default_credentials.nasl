#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47714);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_name(english:"JBoss Administration Console Default Credentials");
  script_summary(english:"Tries to access JBoss administration console with admin/admin");

  script_set_attribute(attribute:"synopsis", value:
"Access to the remote administration console is protected with default
credentials.");
  script_set_attribute(attribute:"description", value:
"The JBoss Administration Console installed on the remote host uses the
default username and password.  Knowing these, an attacker can gain
administrative control of the affected application.");
  script_set_attribute(attribute:"solution", value:"Change the credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/jboss");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

get_kb_item_or_exit("www/jboss");
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# JBoss appears open to be slow and we do not want to do a false negative
http_set_read_timeout(get_read_timeout() * 2);

port = get_http_port(default:8080, embedded:0);

clear_cookiejar(); enable_cookiejar();

pr = "/admin-console/secure/summary.seam";

r = http_send_recv3(method:"GET", item: pr, port: port, exit_on_fail: TRUE, follow_redirect: 2);
if (r[0] =~ "^HTTP/1\.[01] (404|5[0-9][0-9]) ")
 exit(0, "The JBoss server on port "+port+" returned either a 404 or 5xx response.");

if (' id="logoutLink">Logout</a>' >< r[2])
  exit(0, "The 'Logout' link appears in "+build_url(port:port, qs: pr)+" before authenticating.");

if (report_paranoia < 1 && "Please login to proceed." >!< r[2] && "login_form:name" >!< r[2])
  exit(0, build_url(port:port, qs:pr)+" does not have a 'login' link.");

r = http_send_recv3(port: port, method:"GET", item:"/admin-console/login.seam",
  exit_on_fail: TRUE, follow_redirect: 2);
if (r[0] !~ "^HTTP/1\.[01] 200 ")
  exit(0, "Could not access the Administration Console's login page on port "+port+".");

# We have to extract ViewState
vs = egrep(string:r[2], pattern: "javax\.faces\.ViewState");
if (vs)
{
  v = eregmatch(string: vs, pattern: ' value="([^"]*)"');
  if (! isnull(v)) vs = v[1];

}
if (! vs)
  debug_print("Could not extract javax.faces.ViewState field on port "+port+".");

user = 'admin'; passw = 'admin';

d = 'login_form=login_form&login_form%3Aname='+user+'&login_form%3Apassword='+passw+'&login_form%3Asubmit=Login';
if (vs) d += '&' + 'javax.faces.ViewState=' + urlencode(str:vs);

r = http_send_recv3(port:port, method:"POST", item: "/admin-console/login.seam",
  content_type: 'application/x-www-form-urlencoded',
  exit_on_fail: TRUE, follow_redirect: 2, data:  d);

r = http_send_recv3(method:"GET", item: pr, port: port, exit_on_fail: TRUE, follow_redirect: 2);

if (r[0] =~ "^HTTP/1\.[01] 200 " && ' id="logoutLink">Logout</a>' >< r[2] &&
    (report_paranoia >= 1 || "Please login to proceed." >!< r[2]) )
{
  if (report_verbosity <= 0)
    security_hole(port: port);
  else
  {
    report =
'\nNessus was able to gain access to the administrative interface using' +
'\nthe following information :' +
'\n' +
'\n  URL      : ' + build_url(port:port, qs: '/admin-console/login.seam') +
'\n  User     : ' + user +
'\n  Password : ' + passw + '\n';
    security_hole(port: port, extra: report);
  }
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "JBoss", build_url(port:port, qs:'/admin-console'));
