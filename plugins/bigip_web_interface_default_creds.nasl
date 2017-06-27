#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76942);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_name(english:"F5 Networks BIG-IP Web Interface Default Credential Check");
  script_summary(english:"Checks for default login credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web administration interface with known
default credentials.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to login to the administrative interface on the remote
F5 Networks BIG-IP device using a known set of default credentials.");
  # http://support.f5.com/kb/en-us/solutions/public/13000/100/sol13148.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec6a297f");
  script_set_attribute(attribute:"solution", value:"Change the password for the 'admin' account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("bigip_web_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80, 443);
  script_require_keys("www/bigip");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:443, embedded:TRUE);

get_kb_item_or_exit("www/" + port + "/bigip");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

install_url = build_url(qs:'/tmui/', port:port);

post_url = '/tmui/logmein.html';

user = "admin";
pass = "admin";

postdata =
  "username=" + user + "&" +
  "passwd=" + pass;

res = http_send_recv3(
  port            : port,
  method          : "POST",
  item            : post_url,
  data            : postdata,
  content_type    : "application/x-www-form-urlencoded",
  exit_on_fail    : TRUE
);

if (
  'BIGIPAuthUsernameCookie=' + user >< res[1] &&
  'BIGIPAuthCookie=' >< res[1]
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n' + 'Nessus was able to gain access using the following URL' +
      '\n' +
      '\n' + '  ' + install_url + '\n' +
      '\n' + 'and the following set of credentials :' +
      '\n' +
      '\n' + '  Username : ' + user +
      '\n' + '  Password : ' + pass + '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "F5 Networks BIG-IP", install_url);
