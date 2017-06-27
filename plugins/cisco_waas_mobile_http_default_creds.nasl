#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71840);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/17 21:12:12 $");

  script_name(english:"Cisco WAAS Mobile Server Web Administration Default Credentials");
  script_summary(english:"Tries to login using default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host uses a default set of
credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The web administration interface for Cisco WAAS Mobile on the remote
web server uses a known default set of credentials ('admin / default)'."
  );
  # http://www.cisco.com/en/US/docs/app_ntwk_services/waas/waas_mobile/v3.5.5/release/note/WAASMobile3.5.5RN.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7ca756d");
  script_set_attribute(attribute:"solution", value:"Change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:wide_area_application_services_mobile");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_waas_mobile_http_detect.nbin");
  script_require_ports("Services/www", 80, 443);
  script_require_keys("www/cisco_waas");
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname      : "cisco_waas",
  port         : port,
  exit_on_fail : TRUE
);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install["dir"];
url = dir + "/Login.aspx";
install_url = build_url(qs:url, port:port);

init_cookiejar();

# Get a valid session cookie
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : url,
  follow_redirect : 3,
  exit_on_fail : TRUE
);

item = eregmatch(pattern:'__VIEWSTATE"[ ]*value="([^"]+)', string:res[2]);
if (isnull(item)) exit(1, "Could not extract __VIEWSTATE information from "+install_url+".");

user = "admin";
pass = "default";

postdata =
  "username=" + user + "&" +
  "password=" + pass + "&" +
  "__VIEWSTATE=" + urlencode(str:item[1]) + "&" +
  "__EVENTARGUMENT=&" +
  "__EVENTTARGET=&" +
  "btnLogin=Login";

res = http_send_recv3(
  port            : port,
  method          : "POST",
  item            : url,
  data            : postdata,
  content_type    : "application/x-www-form-urlencoded",
  exit_on_fail    : TRUE,
  follow_redirect : 2
);

if (
  '.ASPXAUTH=' >< res[1] &&
  'Cisco WAAS Mobile Manager' >< res[2] && '>Manage<' >< res[2] &&
  '>Configure<' >< res[2] && '>Apply Settings<' >< res[2]
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

    report = get_vuln_report(
      items   : url,
      port    : port,
      header  : header,
      trailer : trailer
    );

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Cisco WAAS Mobile Server", install_url);
