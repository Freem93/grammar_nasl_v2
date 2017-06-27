#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76778);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_name(english:"WebTitan Web Interface Default Credentials");
  script_summary(english:"Attempts to log in with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"A web application is protected using default administrative
credentials.");
  script_set_attribute(attribute:"description", value:
"The remote WebTitan web interface uses a default set of credentials
('admin' / 'hiadmin') to control access to its management interface. A
remote, unauthenticated attacker could exploit this to log in as a
privileged user and gain administrative access to the application.");
  script_set_attribute(attribute:"solution", value:"Log into the application and change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webtitan:webtitan");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("webtitan_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/webtitan");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
app = 'WebTitan';

user = "admin";
pass = "hiadmin";

install = get_install_from_kb(
  appname:'webtitan',
  port:port,
  exit_on_fail:TRUE
);

dir = install['dir'];
url = dir + "/login-x.php";
install_url = build_url(qs:'dir', port:port);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

clear_cookiejar();
postdata = "jaction=login&language=en_US&username="+user+"&password="+pass;

res = http_send_recv3(
  method:"POST",
  item:url,
  port:port,
  data:postdata,
  add_headers:make_array("Content-Type", "application/x-www-form-urlencoded"),
  exit_on_fail:TRUE
);

if ('[{"success":true,"status":"Success: Changes saved"}]' >< res[2])
{
  if (report_verbosity > 0)
  {
    header = 'Nessus was able to gain access using the following URL';
    trailer =
      'and the following set of credentials :' +
      '\n' +
      '\n  Username : ' + user +
      '\n  Password : ' + pass;

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
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
