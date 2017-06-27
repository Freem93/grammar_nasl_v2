#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91100);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/03 14:37:47 $");

  script_cve_id("CVE-2016-4029", "CVE-2016-6634", "CVE-2016-6635");
  script_bugtraq_id(92355, 92390, 92400);
  script_osvdb_id(137859, 137860, 137861);

  script_name(english:"WordPress 4.4.x < 4.5.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is 4.4.x prior to 4.5.0.
It is, therefore, affected by the following vulnerabilities :

  - A server-side request forgery vulnerability exists due
    improper request handling between a user and the server.
    An attacker can exploit this, via a specially crafted
    request to the http.php script using octal or
    hexadecimal IP addresses, to bypass access restrictions
    and perform unintended actions. (CVE-2016-4029)

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input to the
    'first_comment_author' parameter. A context-dependent
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2016-6634)

  - A cross-site request forgery vulnerability exists due to
    a failure to require multiple steps, explicit
    confirmation, or a unique token when making HTTP
    requests. An attacker can exploit this by convincing a
    user to follow a specially crafted link. (CVE-2016-6635)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://wpvulndb.com/vulnerabilities/8473");
  script_set_attribute(attribute:"see_also", value:"https://wpvulndb.com/vulnerabilities/8474");
  script_set_attribute(attribute:"see_also", value:"https://wpvulndb.com/vulnerabilities/8475");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_4.5#Security");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

if (version =~ "^4$")
  audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

# Per https://wordpress.org/download/release-archive/
# only 4.5.x is currently supported :
# "None of these are safe to use, except the latest in the 4.5 series, which is actively maintained."
# Also since 4.5.0 is the first of the 4.5 branch, we only concern ourselves with 4.4.x :
if (version !~ "^4\.4($|[^0-9])")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);

report =
  '\n  URL               : ' + install_url +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : 4.5.0' +
  '\n';
security_report_v4(severity:SECURITY_WARNING, port:port, extra:report, xss:TRUE, xsrf:TRUE);
