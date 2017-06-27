#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81822);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_name(english:"ManageEngine NetFlow Analyzer Default Credentials");
  script_summary(english:"Tries to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The application on the remote web server uses a default set of known
credentials.");
  script_set_attribute(attribute:"description", value:
"The remote ManageEngine NetFlow Analyzer web administration interface 
uses a known set of default credentials. An attacker can use these to
gain access to the system.");
  script_set_attribute(attribute:"solution", value:"Change the default 'admin' login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:netflow_analyzer");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("manageengine_netflow_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/ManageEngine NetFlow Analyzer");

  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

function check_login(user,pass,port,ver)
{
  local_var res,post,item;
  clear_cookiejar();

  item = "/netflow/jspui/NetworkSnapShot.jsp";
  if(ver =~ "^(5|6|7|8)\.")
    item = "/netflow/jspui/index.jsp";

  # Get a SID first, newer versions of tomcat don't
  # set JSESSIONID on j_security_check, so you have
  # to try to get a protected resource first, the
  # SID is resource specific
  res = http_send_recv3(
    method       : "GET",
    port         : port,
    item         : item,
    exit_on_fail : TRUE
  );

  if (empty_or_null(res)) return FALSE;

  post = 'j_username='+user+'&'+
         'j_password='+pass+'&'+
         'AUTHRULE_NAME=Authenticator&' +
         'radiusUserEnabled=false&' +
         'Submit=Login';

  res = http_send_recv3(
    port         : port,
    method       : 'POST',
    item         : "/netflow/j_security_check",
    data         : post,
    content_type : "application/x-www-form-urlencoded",
    exit_on_fail : TRUE
  );


  # Login failed
  if (empty_or_null(res) ||  "302 Moved Temporarily" >!< res[0] || "isLoginPage: true" >< res[1])
    return FALSE;

  # We're authenticated now, get the page we want
  res = http_send_recv3(
    method       : "GET",
    port         : port,
    item         : item,
    exit_on_fail : TRUE
  );

  if (empty_or_null(res) || "403" >< res[0])
    return FALSE;
  else if ('id="adminImg"' >< res[2]) # Version 6 -7 ish
    return TRUE;
  else if (res[1] =~ "iamcsrfcookie=([a-z0-9\-]+);") # Version 8+
    return TRUE;
  return FALSE;
}

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

app = "ManageEngine NetFlow Analyzer";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8080);

install = get_single_install(
  app_name            : app,
  port                : port,
  exit_if_unknown_ver : TRUE
);

url      = build_url(port:port, qs:install["path"]);
cred     = "admin";
logincgi = "/netflow/j_security_check";

if (check_login(user:cred,pass:cred,port:port,ver:install['version']))
{
  if (report_verbosity > 0)
  {
    report  = '\n  Username : ' + cred +
              '\n  Password : ' + cred +
              '\n';
    header  = 'Nessus was able to gain access using the following URL';
    trailer = 'and the following set of credentials :\n' + report;
    report  = get_vuln_report(
      items   : logincgi,
      port    : port,
      header  : header,
      trailer : trailer
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);
