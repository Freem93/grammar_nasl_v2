#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97635);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/26 15:50:24 $");

  script_bugtraq_id(
    96598,
    96600,
    96601,
    96602
  );
  script_osvdb_id(
    153007,
    153008,
    153009,
    153010,
    153011,
    153012,
    153022
  );

  script_name(english:"WordPress 4.7.x < 4.7.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is 4.7.x prior to 4.7.3.
It is, therefore, affected by multiple vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists in the
    wp_playlist_shortcode() function within the
    /wp-includes/media.php script due to a failure to
    validate input passed via audio file metadata before
    returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (VulnDB 153007)

  - A cross-site redirection vulnerability exists due to
    a failure to validate input passed via control
    characters before returning it to users. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted link, to redirect a user from an
    intended legitimate website to an arbitrary website of
    the attacker's choosing. (VulnDB 153008)

  - An unspecified flaw exists in the plugin deletion
    functionality that allows an authenticated, remote
    attacker to delete unintended files. (VulnDB 153009)

  - A cross-site scripting (XSS) vulnerability exists due to
    a failure to validate input to video URLs in YouTube
    embeds before returning it to users. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session. (VulnDB 153010)

  - A cross-site scripting (XSS) vulnerability exists due to
    a failure to validate input to taxonomy term names
    before returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (VulnDB 153011)

  - A cross-site request forgery (XSRF) vulnerability exists
    in the Press This functionality, specifically within
    /wp-admin/press-this.php when handling HTTP requests,
    due to a failure to require multiple steps, explicit
    confirmation, or a unique token when performing certain
    sensitive actions. An unauthenticated, remote attacker
    can exploit this, by convincing a user to follow a
    specially crafted link, to cause excessive consumption
    of server resources. (VulnDB 153012)

  - A DOM-based cross-site scripting (XSS) vulnerability
    exists in the renderTracks() function within the
    /wp-includes/js/mediaelement/wp-playlist.min.js script
    due to a failure to validate input passed via audio file
    metadata before returning it to users. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (VulnDB 153022)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://wordpress.org/news/2017/03/wordpress-4-7-3-security-and-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?071b0e36");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_4.7.3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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
# only 4.7.x is currently supported :
# "None of these are safe to use, except the latest in the 4.7 series, which is actively maintained."
if (version !~ "^4\.7($|(\.[012])($|[^0-9]))")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);

report =
  '\n  URL               : ' + install_url +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : 4.7.3' +
  '\n';
security_report_v4(severity:SECURITY_WARNING, port:port, extra:report, xss:TRUE, xsrf:TRUE);
