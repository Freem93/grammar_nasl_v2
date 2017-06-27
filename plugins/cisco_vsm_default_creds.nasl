#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69855);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/17 21:12:12 $");

  script_name(english:"Cisco Video Surveillance Manager Default Administrator Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application is protected using default administrative
credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco Video Surveillance Manager install uses a default set
of credentials ('root' / 'secur4u') to control access to its management
interface.

With this information, an attacker can gain administrative access to the
application."
  );
  script_set_attribute(attribute:"solution", value:
"Log into the application and change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:video_surveillance_manager");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_vsm_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/cisco_vsm");
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
app = "Cisco Video Surveillance Management Console";

install = get_install_from_kb(
  appname      : "cisco_vsm",
  port         : port,
  exit_on_fail : TRUE
);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install["dir"];
install_url = build_url(qs:dir, port:port);

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

user = "root";
pass = "secur4u";
url = dir + "/console";

res = http_send_recv3(
  method : "GET",
  item   : url,
  port   : port,
  exit_on_fail : TRUE
);

if ('WWW-Authenticate: Basic realm="Video Surveillance Manager Console"' >< res[1])
{
  res2 = http_send_recv3(
    method : "GET",
    item   : url,
    port   : port,
    username : user,
    password : pass,
    exit_on_fail : TRUE
  );

  if(
    res2[0] !=~ "^HTTP/[01.]+ 401 Authorization Required" &&
    res2[0] =~ "^HTTP/[01.]+ 30[12] "
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
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
