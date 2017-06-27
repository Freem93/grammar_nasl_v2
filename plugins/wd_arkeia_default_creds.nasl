#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74218);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_name(english:"Western Digital Arkeia Virtual Appliance Blank Password");
  script_summary(english:"Tries to login with blank password");

  script_set_attribute(attribute:"synopsis", value:"A web application is protected using a blank password.");
  script_set_attribute(attribute:"description", value:
"The remote Western Digital Arkeia Virtual Appliance uses a blank
password to control access to its management interface. With this
information, an attacker can gain administrative access to the web
administration interface for the appliance.");
  script_set_attribute(attribute:"solution", value:"Log into the application and set a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wdc:arkeia_virtual_appliance");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("wd_arkeia_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/PHP", "www/wd_arkeia");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE, embedded:TRUE);

install = get_install_from_kb(
  appname      : "wd_arkeia",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
ver = install["ver"];
install_url = build_url(qs:dir, port:port);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

n = 0;
info = "";
url = dir + "/login/doLogin";

users[n] = "root";
pass[n] = "";
n++;

users[n] = "admin";
pass[n] = "";
n++;

for (i=0; i<n; i++)
{
  clear_cookiejar();
  postdata = "lang=en&password=" + pass[i] + "&username=" + users[i];

  res = http_send_recv3(
    port            : port,
    method          : "POST",
    item            : url,
    data            : postdata,
    content_type    : "application/x-www-form-urlencoded",
    exit_on_fail    : TRUE
  );

  if (
   (
     '"STATUS":["0"],"MESSAGE":[""]' >< res[2] ||
     ("url:." >< res[2] && res[1] =~ "Set-Cookie")
   ) &&
   'Bad password or login' >!< res[2]
  )
  {
    info +=
      '\n  Username : ' + users[i]+
      '\n  Password : ' + pass[i] + '\n';
    if (!thorough_tests) break;
  }
}
if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 4) s = "s";
    else s = "";

    report =
      '\n' + 'Nessus was able to gain access using the following URL :\n' +
      '\n' + '  ' + build_url(port:port, qs:url) +
      '\n' +
      '\n' + 'and the following set' + s + ' of credentials :' +
      '\n' + info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Western Digital Arkeia", install_url);
