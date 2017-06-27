#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24874);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/09/30 16:07:22 $");

  script_cve_id("CVE-2007-1647");
  script_osvdb_id(43558);
  script_xref(name:"EDB-ID", value:"3508");

  script_name(english:"Moodle 'moodledata/sessions' Session Files Remote Information Disclosure");
  script_summary(english:"Checks whether moodledata is accessible.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Moodle on the remote host allows a remote attacker to
browse session files, which likely contain sensitive information about
users of the application, such as password hashes and email addresses.");
  script_set_attribute(attribute:"see_also", value:"http://docs.moodle.org/en/Configuration_file");
  script_set_attribute(attribute:"solution", value:
"Either configure the web server to prevent directory listing or
configure the application so its 'dataroot' is located outside the web
server's documents directory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moodle:moodle");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Moodle");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Moodle";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

init_cookiejar();
# Get the session id.
r = http_send_recv3(method: "GET", item:dir + "/index.php", port:port, exit_on_fail:TRUE);

sid = get_http_cookie(name: "MoodleSession");
# If we have a session cookie...
if (!isnull(sid))
{
  # Try to exploit the flaw.
  r = http_send_recv3(method: "GET", item:dir + "/moodledata/sessions/", port:port, exit_on_fail:TRUE);

  # There's a problem if our session file shows up in the listing.
  if ('href="sess_' + sid + '">sess_' >< r[2])
  {
    security_warning(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
