#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88579);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/02/03 14:37:47 $");

  script_cve_id("CVE-2016-2221", "CVE-2016-2222");
  script_bugtraq_id(82454, 82463);
  script_osvdb_id(133900, 133901);

  script_name(english:"WordPress 4.4.x < 4.4.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is 4.4.x prior to 4.4.2.
It is, therefore, affected by the following vulnerabilities :

  - A cross-site redirection vulnerability exists due to a
    failure by the application to validate certain input.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted link, to redirect a victim from
    a legitimate web site to an arbitrary web site of the
    attacker's choosing, thus allowing further attacks on
    client-side software, such as web browsers or document
    rendering software. (CVE-2016-2221)

  - A server-side request forgery vulnerability exists in
    which the server can be induced into performing
    unintended actions when handling certain requests. An
    unauthenticated, remote attacker can exploit this, via
    crafted requests to certain local URIs, to conduct
    further host-based attacks, such as bypassing access
    restrictions, conducting port scanning, enumerating
    internal networks and hosts, or invoking additional
    protocols. (CVE-2016-2222)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://wpvulndb.com/vulnerabilities/8376");
  script_set_attribute(attribute:"see_also", value:"https://wpvulndb.com/vulnerabilities/8377");
  # https://wordpress.org/news/2016/02/wordpress-4-4-2-security-and-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d40090f8");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_4.4.2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
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

if (version =~ "^4(\.4)?$")
  audit(AUDIT_VER_NOT_GRANULAR, app, port, version);
if (version !~ "^4\.4($|[^0-9])")
  audit(AUDIT_WEB_APP_NOT_INST, app + " 4.4.x", port);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed per https://wpvulndb.com/vulnerabilities/8376 and
# https://wpvulndb.com/vulnerabilities/8376 :
#   3.7.13
#   3.8.13
#   3.9.11
#   4.0.10
#   4.1.10
#   4.2.7
#   4.3.3
#   4.4.2
#
# However, per https://wordpress.org/download/release-archive/
# only 4.4x is currently supported :
# "None of these are safe to use, except the latest in the 4.4 series, which is actively maintained."
# Thus, we only concern ourselves with 4.4.x :
if (ver[0] == 4 && ver[1] == 4 && ver[2] < 2)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.4.2' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
