#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66721);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_name(english:"Junos Space WebUI Default Credentials");
  script_summary(english:"Tries to login with the default username/password");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host is protected using default
credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Junos Space WebUI interface on the remote host has the 'super' user
account secured with the default password.  A remote, unauthenticated
attacker could exploit this to gain administrative access to the web
interface."
  );
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=KB26220");
  script_set_attribute(attribute:"solution", value:"Secure the 'super' user account with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_space_webui_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/junos_space");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);

install = get_install_from_kb(appname:'junos_space', port:port, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

url = install['dir'] + '/';
full_url = build_url(qs:url, port:port);

res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

# newer versions of Space WebUI require the IP address and a random code
# to be included with the login request
match = eregmatch(string:res[2], pattern:"ipAddr = '([^']+)'");
if (!isnull(match))
{
  ipaddr = match[1];

  match = eregmatch(string:res[2], pattern:"code = '([^']+)'");
  if (isnull(match))
    exit(1, 'Unable to extract "code" from ' + full_url);
  else
    code = match[1];
}
else ipaddr = NULL;

user = 'super';
pass = 'juniper123';
set_http_cookie(name:'opennmsuser', value:user);
set_http_cookie(name:'opennmspw', value:pass);

if (isnull(ipaddr))
  postdata = 'j_username=' + user;
else
  postdata = 'j_username=' + user + '%25' + code + '%40' + ipaddr;  # j_username=username%832800821@10.1.1.1

postdata +=
  '&j_screen_username=' + user +
  '&j_password=' + pass +
  '&login=Log+In';
url = install['dir'] + '/j_security_check';
res = http_send_recv3(
  method:'POST',
  item:url,
  port:port,
  content_type:'application/x-www-form-urlencoded',
  data:postdata,
  follow_redirect:2,
  exit_on_fail:TRUE
);

if (
  'The username or password is incorrect.' >< res[2] ||
  '<title>Junos Space Network Application Platform' >!< res[2]
)
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Junos Space', full_url);
}

# the plugin isn't interested in the response, it just wants
# to make an attempt to log out
url = install['dir'] + '/unsecured/logout';
http_send_recv3(method:'GET', item:url, port:port);

if (report_verbosity > 0)
{
  report =
    '\nNessus was able to log into the Junos Space WebUI using the' +
    '\nfollowing information :' +
    '\n' +
    '\n  URL      : ' + full_url +
    '\n  Username : ' + user +
    '\n  Password : ' + pass + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
