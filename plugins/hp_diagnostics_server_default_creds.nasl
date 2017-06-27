#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64474);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/18 20:40:53 $");

  script_name(english:"HP Diagnostics Server Default Credentials");
  script_summary(english:"Tries to login using default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a web application with default login
credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to login to the HP Diagnostics Server web interface
using default, known credentials."
  );
  # ftp://ftp.itrc.hp.com/applications/HPSoftware/ONLINE_HELP/Diagnostic9.20_Users.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?484d615c");
  script_set_attribute(attribute:"solution", value:"Change the default password for built-in accounts.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:diagnostics_server");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_diagnostics_server_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 2006);
  script_require_keys("www/hp_diagnostics_server");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:2006);

install = get_install_from_kb(appname:"hp_diagnostics_server", port:port, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install['dir'];
version = install['ver'];
location = build_url(qs:dir + '/', port:port);


res = http_send_recv3(
  method:'GET',
  item:dir + '/maintenance/',
  port:port,
  username:'admin',
  password:'admin',
  exit_on_fail:TRUE
);

if (
  "Built-In User Management" >< res[2] &&
  "Configuration" >< res[2] &&
  "License Management" >< res[2] &&
  "Access denied" >!< res[2]
)
{
  if (report_verbosity > 0)
  {
    report = '\nNessus was able to gain access using the following information :\n' +
             '\n  URL      : ' + location +
             '\n  User     : admin' +
             '\n  Password : admin\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "HP Diagnostics Server", location);
