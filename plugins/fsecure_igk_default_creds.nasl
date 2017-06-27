#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(52025);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/08 20:42:13 $");

  script_name(english:"F-Secure Internet Gatekeeper Default Administrator Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application is protected using default administrative
credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote F-Secure Internet Gatekeeper install uses a default set of
credentials ('admin' / 'admin') to control access to its Web Console. 

With this information, an attacker can gain administrative access to the
application."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Log into the Web Console, click 'Admin password', and change the
password."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:f-secure:internet_gatekeeper");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("fsecure_igk_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/fsecure_igk");
  script_require_ports("Services/www", 9012);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:9012, embedded:FALSE);

install = get_install_from_kb(appname:'fsecure_igk', port:port, exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
dir = install['dir'];

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();


# Identify form values that we need for logging in.
url = dir + '/login.jsf';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

viewstate = NULL;
match = egrep(pattern:"javax\.faces\.ViewState.+value=", string:res[2]);
if (match)
{
  value = eregmatch(pattern:'javax\\.faces\\.ViewState.+ value="([^"]+)"', string:match);
  if (!isnull(value)) viewstate = value[1];
}
if (isnull(viewstate)) exit(1, "Failed to extract the javax.faces.ViewState value from the install at "+build_url(port:port, qs:url)+".");

idcl = NULL;
match = egrep(pattern:"oamSubmitForm.+'form:j_id_jsp_.+>Login</a>", string:res[2]);
if (match)
{
  value = eregmatch(pattern:"'form:(j_id_jsp_[^' ;]+)'", string:match);
  if (!isnull(value)) idcl = value[1];
}
if (isnull(idcl)) exit(1, "Failed to extract the linkId value from the install at "+build_url(port:port, qs:url)+".");


# Try to log in.
user = "admin";
pass = "admin";

postdata =
  urlencode(str:'form:username') + '=' + urlencode(str:user) + '&' +
  urlencode(str:'form:password') + '=' + urlencode(str:pass) + '&' +
  urlencode(str:'form:changelang') + '=EN&' +
  'form_SUBMIT=1&' +
  'javax.faces.ViewState=' + urlencode(str:viewstate) + '&' +
  urlencode(str:'form:_idcl') + '=' + urlencode(str:'form:'+idcl);

res = http_send_recv3(
  port            : port,
  method          : 'POST',
  item            : url,
  data            : postdata,
  content_type    : "application/x-www-form-urlencoded",
  exit_on_fail    : TRUE
);

hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(hdrs['$code'])) code = 0;
else code = hdrs['$code'];

if (isnull(hdrs['location'])) location = "";
else location = hdrs['location'];

# There's a problem if we're redirected to /home.jsf
if (
  code == 302 &&
  "/home.jsf" >< location
)
{
  if (report_verbosity > 0)
  {
    header = 'Nessus was able to gain access using the following URL';
    trailer =
      'and the following set of credentials :\n' +
      '\n' +
      '  Username : ' + user + '\n' +
      '  Password : ' + pass;

    report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "F-Secure Internet Gatekeeper", build_url(port:port, qs:dir+'/login.jsf'));
