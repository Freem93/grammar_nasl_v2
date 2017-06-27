#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51460);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_name(english:"Openfiler Management Interface Default Administrator Credentials");
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
"The remote Openfiler install uses a default set of credentials
('openfiler' / 'password') to control access to its management
interface. 

With this information, an attacker can gain administrative access to the
application."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Log into the Openfiler management interface and change the Admin
password."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("openfiler_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/openfiler");
  script_require_ports("Services/www", 446);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:446, embedded:FALSE);

install = get_install_from_kb(appname:'openfiler', port:port, exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install['dir'];

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

# Try to log in.
url = dir + '/account/login.html';

user = 'openfiler';
pass = 'password';

postdata =
  'username=' + user + '&' +
  'password=' + pass;

res = http_send_recv3(
  port            : port,
  method          : 'POST',
  item            : url,
  data            : postdata,
  content_type    : "application/x-www-form-urlencoded",
  follow_redirect : 1,
  exit_on_fail    : TRUE
);

if (
  '<title>Status : System Status' >< res[2] &&
  '>Mounted Filesystems</td>' >< res[2] &&
  '>Openfiler</a>. All rights reserved.' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    header = 'Nessus was able to gain access using the following URL';
    trailer =
      'and the following set of credentials :\n' +
      '\n' +
      '  Username : ' + user + '\n' +
      '  Password : ' + pass + '\n';

    report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "Openfiler", build_url(port:port, qs:dir));
