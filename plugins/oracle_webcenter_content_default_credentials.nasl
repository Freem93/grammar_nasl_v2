#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57978);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 23:21:18 $");

  script_name(english:"Oracle WebCenter Content Default Administration Credentials");
  script_summary(english:"Try logging into WebCenter Content using default administrative credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The administration console for the remote content management system
is protected using a known set of credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to login to Oracle WebCenter Content using a default
set of administrative credentials.  A remote attacker could utilize
these credentials to view and delete protected content or change the
content server configuration."
  );
  script_set_attribute(attribute:"see_also", value:"http://docs.oracle.com/cd/E14571_01/core.1111/e12037/contentsvr.htm");
  script_set_attribute(attribute:"solution", value:"Change passwords on any default accounts.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_webcenter_content_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/supplied_logins_only");
  script_require_keys("installed_sw/Oracle WebCenter Content");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app_name = "Oracle WebCenter Content";

get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(app_name:app_name, port:port);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install['path'];

install_url = build_url(port: port, qs:dir);

url_http_login = dir + '/idc/idcplg?IdcService=GET_DOC_PAGE&Action=GetTemplatePage&Page=HOME_PAGE&Auth=Internet';
url_post_login = dir + '/login/j_security_check';

res = http_send_recv3(
  method:"GET",
  item:url_post_login,
  port:port,
  exit_on_fail:TRUE);

is_http = TRUE;
if ('IdcClientLoginForm' >< res[2]) is_http = FALSE;

username_list = make_list("weblogic", "sysadmin");
password_lists = make_array();

# default account lock for 11g is 5 attempts
password_lists["sysadmin"] = make_list("idc", "welcome1");
password_lists["weblogic"] = make_list("welcome1", "weblogic1");


function login()
{
  local_var headers, location, user, pass, res, res_hdrs, postdata, logged_in, is_http;
  user = _FCT_ANON_ARGS[0];
  pass = _FCT_ANON_ARGS[1];
  is_http = _FCT_ANON_ARGS[2];
  logged_in = FALSE;

  if (is_http)
  {
    res = http_send_recv3(
      method:'GET',
      item:url_http_login,
      username:user,
      password:pass,
      follow_redirect:3,
      port:port,
      exit_on_fail:TRUE
    );
    if ('Home Page for sysadmin' >< res[2]) logged_in = TRUE;
  }
  else
  {
    clear_cookiejar();

    postdata =
    'j_character_encoding=UTF-8'+
    '&j_username='+user+
    '&j_password='+pass;

    res = http_send_recv3(
       method:'POST',
       item:url_post_login,
       data:postdata,
       content_type:'application/x-www-form-urlencoded',
       port:port,
       exit_on_fail:TRUE
    );

    headers = parse_http_headers(status_line:res[0], headers:res[1]);
    if (!isnull(headers))
    {
      location = headers['location'];
      if (!isnull(location))
      {
        # redirect on successful login
        if (';jsessionid' >< location) logged_in = TRUE;
      }
    }
  }
  return logged_in;
}


report = "";
foreach username (username_list)
{
  foreach password (password_lists[username])
  {
    if (login(username, password, is_http))
    {
      report +=
        '\n  Username : ' + username +
        '\n  Password : ' + password +
        '\n';

      # nb: If we found a password that works, there's no need to try
      #     the next password for the same user.
      break;
    }
  }
}
if (!report) audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url);

if (report_verbosity > 0)
{
  report =
    '\n' + 'It is possible to log into the Oracle WebCenter Content Server at the' +
    '\n' + 'following URL :' +
    '\n' +
    '\n' + install_url +
    '\n' +
    '\n' + 'with these credentials :' +
    report;
  security_hole(port:port, extra:report);
}
else security_hole(port);
