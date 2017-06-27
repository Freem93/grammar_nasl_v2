#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63693);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_name(english:"ManageEngine AssetExplorer Default Administrator Credentials");
  script_summary(english:"Attempts to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"A web application is protected using default administrative
credentials.");
  script_set_attribute(attribute:"description", value:
"The ManageEngine AssetExplorer application running on the remote host
uses a default set of credentials ('administrator' / 'administrator')
to control access to its management interface. A remote attacker can
exploit this to gain administrative access to the application.");
  script_set_attribute(attribute:"see_also", value:"http://www.manageengine.com/products/asset-explorer/");
  script_set_attribute(attribute:"solution", value:
"Log into the application and personalize the account to change the
default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:zohocorp:manageenginer_assetexplorer");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_assetexplorer_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/ManageEngine AssetExplorer");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "ManageEngine AssetExplorer";
get_install_count(app_name : appname, exit_if_zero : TRUE);
port = get_http_port(default : 8080);
install = get_single_install(
  app_name : appname,
  port : port
);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install['path'];
install_url = build_url(port:port, qs:dir+"/");

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

user = 'administrator';
pass = 'administrator';

# Obtain Session Cookie
url= '/';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

val = get_http_cookie(name:"JSESSIONID");
if (isnull(val)) exit(1, "Failed to extract the session cookie from the " + appname + " install.");

data = "j_username="+ user+ "&j_password="+ pass+ "&AUTHRULE_NAME=Authenticator&Submit";

url = '/j_security_check';
res = http_send_recv3(
  method:"POST", 
  item:url, 
  port:port, 
  content_type:"application/x-www-form-urlencoded",
  follow_redirect:2,
  data:data,
  exit_on_fail:TRUE
);
if (
  "<strong>Log out</strong></a>" >< res[2] &&
  "[ administrator ]" >< res[2] &&
  egrep(pattern:'<title>ManageEngine AssetExplorer</title>', string:res[2])
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to gain access using the following URL :' +
      '\n' +
      '\n' + '  ' + build_url(port:port, qs:url) +
      '\n' +
      '\n' + 'and the following set of credentials :' +
      '\n' +
      '\n  Username : ' + user +
      '\n  Password : ' + pass + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);
