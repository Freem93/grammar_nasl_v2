#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(49698);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_name(english:"Mura CMS Default Administrator Credentials");
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
"The remote Mura CMS install uses a default set of credentials ('admin'
/ 'admin') to control access to the Mura Admin. 

With this information, an attacker can gain administrative access to the
application."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Log into the Mura Admin, select 'Edit Profile', and change the
password."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("mura_cms_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/mura_cms");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, embedded:FALSE);

install = get_install_from_kb(appname:'mura_cms', port:port, exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
dir = install['dir'];


# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

# Try to log in.
url = dir + '/admin/index.cfm?fuseaction=cLogin.main';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);


user = "admin";
pass = "admin";

postdata =
  'username=' + user + '&' +
  'password=' + pass + '&' +
  'rb=en&' +
  'returnUrl=&' +
  'fuseaction=cLogin.login';

res = http_send_recv3(
  port            : port,
  method          : 'POST',
  item            : url,
  data            : postdata,
  content_type    : "application/x-www-form-urlencoded",
  follow_redirect : 3,
  exit_on_fail    : TRUE
);

if (
  'Dashboard</title>' >< res[2] &&
  'fuseaction=cPrivateUsers.list' >< res[2]
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
audit(AUDIT_WEB_APP_NOT_AFFECTED, "Mura CMS", build_url(port:port, qs:dir));
