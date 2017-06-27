#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93516);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/01 21:55:33 $");

  script_cve_id("CVE-2016-7168", "CVE-2016-7169");
  script_osvdb_id(143887, 143888);

  script_name(english:"WordPress 4.6.x < 4.6.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is 4.6.x prior to 4.6.1.
It is, therefore, affected by multiple vulnerabilities :

  - A cross-site scripting vulnerability (XSS) exists when
    handling file names of uploaded images due to improper
    validation of input before returning it to users. An
    authenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2016-7168)

  - A path traversal vulnerability exists in the WordPress
    upgrade package uploader due to improper sanitization of
    user-supplied input. An authenticated, remote attacker
    can exploit this, via a specially crafted request, to
    impact confidentiality, integrity, and availability.
    (CVE-2016-7169)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://wordpress.org/news/2016/09/wordpress-4-6-1-security-and-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be1e697e");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_4.6.1");
  script_set_attribute(attribute:"see_also", value:"https://core.trac.wordpress.org/query?milestone=4.6.1");
  # https://sumofpwn.nl/advisory/2016/persistent_cross_site_scripting_vulnerability_in_wordpress_due_to_unsafe_processing_of_file_names.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0366a41c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/15");

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
# only 4.6.x is currently supported :
# "None of these are safe to use, except the latest in the 4.6 series, which is actively maintained."
if (version !~ "^4\.6($|(\.0)($|[^0-9]))")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);

report =
  '\n  URL               : ' + install_url +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : 4.6.1' +
  '\n';
security_report_v4(severity:SECURITY_HOLE, port:port, extra:report, xss:TRUE);
