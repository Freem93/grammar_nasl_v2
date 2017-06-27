#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81380);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id("CVE-2015-7765");
  script_osvdb_id(127464);
  script_xref(name:"EDB-ID", value:"38174");
  script_xref(name:"EDB-ID", value:"38221");

  script_name(english:"ManageEngine OpManager Default Credentials");
  script_summary(english:"Attempts to login with default credentials.");
  
  script_set_attribute(attribute:"synopsis", value:
"The application hosted on the remote web server uses a default set of
known credentials.");
  script_set_attribute(attribute:"description", value:
"The remote ManageEngine OpManager web administration interface uses a
known set of hard-coded default credentials. An attacker can use these
to gain administrative access to the remote host.");
  # https://support.zoho.com/portal/manageengine/helpcenter/articles/pgsql-submitquery-do-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63ab713a");
  # https://packetstormsecurity.com/files/133582/ManageEngine-OpManager-11.5-Hardcoded-Credential-SQL-Bypass.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f76ba3d");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2015/Sep/66");
  script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ManageEngine OpManager Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/09/14");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_opmanager");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_opmanager_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/ManageEngine OpManager");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

function check_login(user,pass,port)
{
  local_var res,post;
  clear_cookiejar();

  post = 'clienttype=html&'+
         'isCookieADAuth=&'+
         'domainName=NULL&'+
         'authType=localUserLogin&'+
         'webstart=&'+
         'ScreenWidth=1672&'+
         'ScreenHeight=502&'+
         'userName='+user+'&'+
         'password='+pass+'&'+
         'signInAutomatically=off&'+
         'uname=';

  res = http_send_recv3(
    port         : port,
    method       : 'POST',
    item         : "/jsp/Login.do",
    data         : post,
    content_type : "application/x-www-form-urlencoded",
    exit_on_fail : TRUE
  );

  # We're authenticated now, get about page
  res = http_send_recv3(
    method       : "GET",
    port         : port,
    item         : "/licenseInfo.do?methodCall=showAboutPage",
    exit_on_fail : TRUE
  );

  if (empty_or_null(res) || "403" >< res[0]) return FALSE;
  #Confirm
  if("Build Number" >< res[2] && "License Type" >< res[2]) return TRUE;
  return FALSE;
}

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

app = "ManageEngine OpManager";
get_install_count(app_name:app, exit_if_zero:TRUE);
port     = get_http_port(default:80);
install  = get_single_install(app_name:app,port:port);

url      = build_url(port:port, qs:install["path"]);
creds    = make_array("admin","admin", "IntegrationUser","plugin");
logincgi = "/jsp/Login.do";
report = "";

# Check each potential credential
foreach cred (keys(creds))
{
  if (check_login(user:cred,pass:creds[cred],port:port))
  {
    report += '\n  Username : ' + cred +
              '\n  Password : ' + creds[cred] ;
    if (cred == "IntegrationUser")
    {
      report += '\n  Fix: Contact the vendor for a patch.' ;
    }
    report +=   '\n';
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
