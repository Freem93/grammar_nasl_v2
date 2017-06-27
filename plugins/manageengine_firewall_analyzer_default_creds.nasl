#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90444);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/04/13 14:32:32 $");

  script_name(english:"ManageEngine Firewall Analyzer Default Credentials");
  script_summary(english:"Attempts to login with default credentials.");
  
  script_set_attribute(attribute:"synopsis", value:
"The application hosted on the remote web server uses a default set of
known credentials.");
  script_set_attribute(attribute:"description", value:
"The remote ManageEngine Firewall web administration interface uses a
known set of hard-coded default credentials. An attacker can exploit
this to gain administrative access to the remote host.");
  script_set_attribute(attribute:"solution", value:
"Change the application's default credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:zohocorp:manageengine_firewall_analyzer");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_firewall_analyzer_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/ManageEngine Firewall Analyzer");
  script_require_ports("Services/www", 8500);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

# Version 12+ are built on OpManager and have an exposed
# REST API
function check_login_post12(user, pass, port)
{
  local_var res,post;
  post = "j_username="+user+"&j_password="+pass;
  # Authenticate
  res = http_send_recv3(
    port         : port,
    method       : 'POST',
    item         : "/api/login",
    data         : post,
    content_type : "application/x-www-form-urlencoded",
    exit_on_fail : TRUE
  );

  if ('productType":"FIREWALL"' >< res[2] && 'status":"Success"' >< res[2])
    return TRUE;
  return FALSE;
}

# Versions before 12.0 are mostly just regular old TomCat
# applications
function check_login_pre12(user, pass, port)
{
  local_var res,post;
  clear_cookiejar();

  # Newer versions of tom cat won't let you do "drive by auth",
  # that is to say, we need to try and access a protected
  # resource first, populate the JSESSIONID before attempting
  # to authenticate via j_security_check
  res = http_send_recv3(
    method       : "GET",
    port         : port,
    item         : "/fw/aboutus.do",
    exit_on_fail : TRUE
  );

  post = 'loginButton=Login&'+
         'j_username='+user+'&'+
         'j_password='+pass+'&'+
         'domain=null&'+
         'domains=local';

  # Authenticate
  res = http_send_recv3(
    port         : port,
    method       : 'POST',
    item         : "/fw/j_security_check",
    data         : post,
    content_type : "application/x-www-form-urlencoded",
    exit_on_fail : TRUE
  );

  # We're authenticated now, get about page
  res = http_send_recv3(
    method       : "GET",
    port         : port,
    item         : "/fw/aboutus.do",
    exit_on_fail : TRUE
  );

  if (empty_or_null(res) || "403" >< res[0])
    return FALSE;

  #Confirm
  if("Build Number" >< res[2] && "Server Type" >< res[2])
    return TRUE;

  return FALSE;
}

# Checks the app version to decide which authentication
# function should be used
function ispost12(version)
{
  # Unknown versions are likely 12+
  if (version == UNKNOWN_VER)
    return TRUE;

  version = eregmatch(pattern:"(^[0-9.]+)([^0-9.]|$)", string:version);
  # Should never happen really, but again assume 12+
  if (empty_or_null(version))
    return TRUE;

  # Check for post12 version
  version = version[1];
  return (ver_compare(ver:version, fix:"12", strict:FALSE) >= 0);
}

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Prevent unnecessary forking
app = "ManageEngine Firewall Analyzer";
get_install_count(app_name:app, exit_if_zero:TRUE);

port     = get_http_port(default:8500);
install  = get_single_install(app_name:app,port:port);
post12   = ispost12(version:install['version']);
url      = build_url(port:port, qs:install["path"]);
users    = make_list("admin", "guest");
passw    = make_array("admin", "admin", "guest", "guest");
report   = "";

# Check each potential credential
foreach cred (users)
{
  canauth = FALSE;
  if (!post12)
    canauth = check_login_pre12(user:cred, pass:passw[cred], port:port);
  else
    canauth = check_login_post12(user:cred, pass:passw[cred], port:port);

  if (canauth)
  {
    report += '\n' +
              '\n  Username : ' + cred +
              '\n  Password : ' + passw[cred];

    if (!thorough_tests || !get_kb_item("Settings/test_all_accounts")) break;
  }
}


if (report != "")
{
  header  = 'Nessus was able to gain access using the following URL';
  trailer = 'and the following set of credentials :' + report;
  report  = get_vuln_report(
    items   : install["path"],
    port    : port,
    header  : header,
    trailer : trailer
  );
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);
