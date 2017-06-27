#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91810);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/06/27 14:51:42 $");

  script_osvdb_id(
    140310,
    140311,
    140312,
    140313,
    140314,
    140315,
    140316
  );

  script_name(english:"WordPress 4.5.x < 4.5.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is 4.5.x prior to 4.5.3.
It is, therefore, affected by the following vulnerabilities :

  - An unspecified flaw exists in the Customizer component
    that allows an unauthenticated, remote attacker to
    perform a redirect bypass. (VulnDB 140310)

  - Multiple cross-site scripting vulnerabilities exist due
    to improper validation of user-supplied input when
    handling attachment names. An unauthenticated, remote
    attacker can exploit these issues, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session. (VulnDB 140311)

  - An information disclosure vulnerability exists that
    allows an unauthenticated, remote attacker to disclose
    revision history. (VulnDB 140312)

  - An unspecified flaw exists in oEmbed that allows an
    unauthenticated, remote attacker to cause a denial of
    service condition. (VulnDB 140313)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to remove categories
    from posts. (VulnDB 140314)

  - An unspecified flaw exists that is triggered when
    handling stolen cookies. An unauthenticated, remote
    attacker can exploit this to change user passwords.
    (VulnDB 140315)

  - Multiple unspecified flaws exist in the
    sanitize_file_name() function that allow an
    unauthenticated, remote attacker to have an unspecified
    impact. (VulnDB 140316)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/news/2016/06/wordpress-4-5-3/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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
# Thus, we only concern ourselves with 4.5.x :
if (version !~ "^4\.5($|(\.[0-2])($|[^0-9]))")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);

report =
  '\n  URL               : ' + install_url +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : 4.5.3' +
  '\n';
security_report_v4(severity:SECURITY_WARNING, port:port, extra:report, xss:TRUE);
