#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34395);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_name(english:"ASG-Sentry CGI Default Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web application is protected with default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote ASG-Sentry CGI script is configured to use default
credentials to control administrative access.  Knowing these, an
attacker can gain administrative control of the affected application.");
  script_set_attribute(attribute:"solution", value:"Change the password for the 'admin' account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("asg_sentry_cgi_detect.nasl");
  script_require_ports("Services/www", 6161);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:6161);

user = "admin";
pass = "admin";


# Test an install.
install = get_kb_item_or_exit("www/" + port + "/asg_sentry");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  url = dir + "/fxm.exe";
  install_url = build_url(qs:url, port:port);

  # Get the form data.
  r = http_send_recv3(port: port, method: 'GET', item: url, exit_on_fail:TRUE);

  cookie = "";
  script_name = "";
  caller = "";
  str = 'ACTION="' + dir + '/fxm.exe?';
  str2 = 'ACTION="' + dir + '/exs.exe?';
  if (str >< r[2])
  {
    cookie = strstr(r[2], str) - str;
    cookie = cookie - strstr(cookie, '"');
    caller = "/s";
    script_name = "fxm_login.s";
  }
  else if (str2 >< res)
  {
    cookie = strstr(res, str2) - str2;
    cookie = cookie - strstr(cookie, '"');
    caller = "/snmx/";
    script_name = "exs_login.s";
  }

  if (cookie)
  {
    # Try to log in.
    postdata =
      "script_name=" + script_name + "&" +
      "caller=" + caller + "&" +
      "access=(null)&" +
      "username=" + user + "&" +
      "password=" + pass + "&" +
      "Login+value=Login";
    r = http_send_recv3(port: port, method: 'POST',
  item: url + '?' + cookie, version: 11, data: postdata,
  add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
  exit_on_fail: TRUE);

    # There's a problem if we see the Exit button.
    if ('<!-- Exit Button -->' >< r[2])
    {
      if (report_verbosity > 0)
      {
        report =
          '\n' +
          'Nessus was able to gain access using the following credentials :\n'+
          '\n' +
          '  URL      : ' + install_url + '\n' +
          '  User     : ' + user + '\n' +
          '  Password : ' + pass + '\n';
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
    }
  }
  else audit(AUDIT_WEB_APP_NOT_AFFECTED, "ASG-Sentry CGI", install_url);
}
else audit(AUDIT_WEB_APP_NOT_INST, "ASG-Sentry CGI", port);
