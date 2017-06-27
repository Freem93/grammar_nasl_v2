#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73121);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/07 20:46:55 $");

  script_name(english:"Oracle BI Publisher Default Credentials Check");
  script_summary(english:"Tries to login using default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a web application that uses a default set of
credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to login to the remote Oracle BI Publisher install
using a known set of default credentials.  This allows a remote attacker
to gain administrative access to the application."
  );
  script_set_attribute(attribute:"see_also", value:"http://netinfiltration.com/");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cef09be");
  script_set_attribute(attribute:"solution", value:"Change the password for any accounts using default credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_bi_publisher_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/Oracle BI Publisher");
  script_require_ports("Services/www", 9704, 8888, 7001);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = 'Oracle BI Publisher';
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:9704);
install = get_single_install(app_name:app_name, port:port);

dir = install['dir'];
version = install['version'];
install_url = build_url(port:port, qs:dir+"/login.jsp");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Later versions prompt for password during install, so don't bother checking those.
if (version != UNKNOWN_VER)
{
  ver = split(version, sep:'.', keep:FALSE);
  if (int(ver[0]) > 10) audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url);
}

# trim trailing /
if (dir[strlen(dir) - 1] == '/')
  dir = substr(dir, 0, strlen(dir) - 2);

init_cookiejar();

postdata =
  'id=Administrator&' +
  'passwd=Administrator';

res = http_send_recv3(
  port            : port,
  method          : 'POST',
  item            : dir + '/login.jsp',
  data            : postdata,
  content_type    : "application/x-www-form-urlencoded",
  follow_redirect : 3,
  exit_on_fail    : TRUE
);

if (
  '<title>Oracle BI Publisher</title>' >< res[2] &&
  'Welcome, Administrator' >< res[2]
)
{
  if (report_verbosity > 0) 
  {
    report = '\n' + 'Nessus was able to login using the following credentials :\n' +
             '\n' + '  URL      : ' + install_url + 
             '\n' + '  Username : Administrator' +
             '\n' + '  Password : Administrator\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url);
