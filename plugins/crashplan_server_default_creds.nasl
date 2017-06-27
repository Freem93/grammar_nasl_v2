#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38952);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/17 21:38:53 $");

  script_name(english:"CrashPlan Server Default Administrative Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web application is protected using default credentials.");
  script_set_attribute( attribute:"description",  value:
"The remote host is running CrashPlan or CrashPlan PRO Server, the
server component of CrashPlan, a cross-platform backup application. 

The remote installation of CrashPlan Server is configured to use default
credentials to control administrative access.  Knowing these, an
attacker can gain administrative control of the affected application.");
  script_set_attribute(attribute:"solution", value:"Change the password for the admin user.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 4280);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:4280, embedded: 0);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

user = "admin";
pass = "admin";


# Pull up the login form.
init_cookiejar();

url = "/manage/login.vtl";
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (
  '<title>CrashPlan' >< res[2] &&
  'action="/manage/login.vtl' >< res[2]
)
{
  # Try to log in.
  cookie = get_http_cookie(name:"jsessionid");
  if (!isnull(cookie)) url2 = url + ";jsessionid=" + cookie;
  else url2 = url;

  postdata =
    "cid=app.loginForm&" +
    "onSuccess=/manage/index.vtl&" +
    "onFailure=/manage/login.vtl?success=/manage/index.vtl&" +
    "onCancel=&" +
    "loginForm.email=" + user + "&" +
    "loginForm.password=" + pass + "&";

  res = http_send_recv3(
    port        : port,
    method      : 'POST',
    item        : url2,
    data        : postdata,
    add_headers : make_array(
      "Content-Type", "application/x-www-form-urlencoded"
    ),
    exit_on_fail : TRUE
  );

  install_url = build_url(port:port, qs:url);
  # There's a problem if we're redirected to the main index.
  if (
    "302 " >< res[0] &&
    egrep(pattern:'^Location: .+/manage/index\\.vtl\\?tid=', string:res[1])
  )
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' +
        'Nessus was able to gain access using the following information :\n' +
        '\n' +
        '  URL      : ' + install_url + '\n' +
        '  Username : ' +  user + '\n' +
        '  Password : ' + pass + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
  else audit(AUDIT_WEB_APP_NOT_AFFECTED, "CrashPlan", install_url);
}
else audit(AUDIT_WEB_APP_NOT_INST, "CrashPlan", port);
