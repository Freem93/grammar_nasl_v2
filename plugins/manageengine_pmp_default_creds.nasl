#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80961);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_name(english:"ManageEngine Password Manager Pro Default Credentials");
  script_summary(english:"Attempts to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The application on the remote web server uses a default set of known
credentials.");
  script_set_attribute(attribute:"description", value:
"The remote ManageEngine Password Manager Pro web administration
interface uses a known set of default credentials. An attacker can use
these to gain access to the remote host.");
  script_set_attribute(attribute:"solution", value:"Change the default 'admin' and 'guest' login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:password_manager_pro");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("manageengine_pmp_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/ManageEngine Password Manager Pro");
  script_require_ports("Services/www", 7272);

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
  local_var res,post,rgx;
  clear_cookiejar();

  # Get a SID first, newer versions of tomcat don't
  # set JSESSIONID on j_security_check, so you have
  # to try to get a protected resource first, the
  # SID is resource specific
  res = http_send_recv3(
    method       : "GET",
    port         : port,
    item         : "/PassTrixMain.cc",
    exit_on_fail : TRUE
  );

  if (empty_or_null(res)) return FALSE;

  if(ver =~ "^(6|7)")
  {
    rgx  = "(GROUP_TYPE=My Favourite Passwords|PassTrixQuickView)";
    post = 'j_username='+user+'&'+
           'j_password='+pass+'&'+
           'domains=Local Authentication&' +
           'loginButton=Login&' +
           'optionValue=hide&'+
           'forChecking=null';
  }
  else # Older versions are a bit different
  {
    rgx  = "(PassTrixGuestTab|PassTrixQuickView)";
    post = 'j_username='+user+'&'+
           'j_password='+pass+'&'+
           'domainName=LOCAL&' +
           'username='+user;
  }

  res = http_send_recv3(
    port         : port,
    method       : 'POST',
    item         : "/j_security_check",
    data         : post,
    content_type : "application/x-www-form-urlencoded",
    exit_on_fail : TRUE
  );

  # Login failed
  if (empty_or_null(res) ||  "302 Moved Temporarily" >!< res[0] || "isLoginPage: true" >< res[1]) return FALSE;

  # We're authenticated now, get about page
  res = http_send_recv3(
    method       : "GET",
    port         : port,
    item         : "/PassTrixMain.cc",
    exit_on_fail : TRUE
  );

  if (empty_or_null(res) || "403" >< res[0]) return FALSE;
  else if (!empty_or_null(eregmatch(pattern:rgx,string:res[2]))) return TRUE;
  return FALSE;
}

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

app = "ManageEngine Password Manager Pro";
get_install_count(app_name:app, exit_if_zero:TRUE);
port     = get_http_port(default:7272);
install  = get_single_install(app_name:app,port:port);

url      = build_url(port:port, qs:install["path"]);
creds    = make_list("admin", "guest");
logincgi = "/j_security_check";

# Check each potential credential
report = "";
foreach cred (creds)
{
  if (check_login(user:cred,pass:cred,port:port,ver:install['version']))
  {
    report += '\n  Username : ' + cred +
              '\n  Password : ' + cred +
              '\n';
    if(cred == "admin")
    {
      report +=
              '\n  Note     : You may also want to check the "guest" account as well';
      break; # If admin is set, that's good enough
    }
  }
}

if (report != "")
{
  if (report_verbosity > 0)
  {
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
