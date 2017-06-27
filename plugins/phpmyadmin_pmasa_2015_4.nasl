#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85986);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/18 13:38:30 $");

  script_cve_id("CVE-2015-6830");
  script_osvdb_id(127397);

  script_name(english:"phpMyAdmin 4.3.x < 4.3.13.2 / 4.4.x < 4.4.14.1 reCaptcha Bypass (PMASA-2015-4)");
  script_summary(english:"Checks the version of phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin
application hosted on the remote web server is 4.3.x prior to 4.3.13.2
or 4.4.x prior to 4.4.14.1. It is, therefore, affected by a security
bypass vulnerability related to reCaptcha processing. An
unauthenticated, remote attacker can exploit this to bypass the
reCaptcha test, resulting in a bypass of brute-force protection.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2015-4.php");
  # 4.3 https://github.com/phpmyadmin/phpmyadmin/commit/0314e67900f01410bc8c81c58a40dc0515e3c91d
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24135dd6");
  # 4.4 https://github.com/phpmyadmin/phpmyadmin/commit/785f4e2711848eb8945894199d5870253a88584e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b092eb7e");

  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin 4.3.13.2 / 4.4.14.1 or later. Alternatively,
apply the patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "installed_sw/phpMyAdmin", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "phpMyAdmin";
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
dir = install['path'];
url = build_url(qs:dir, port:port);
version = install['version'];

if (version =~ "^4(\.[34])?$") audit(AUDIT_VER_NOT_GRANULAR, appname, port, version);
if (version !~ "^4\.[34][^0-9]") audit(AUDIT_WEB_APP_NOT_INST, appname + " 4.3.x / 4.4.x", port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

re = make_array(
  -2, "-beta(\d+)",
  -1, "-rc(\d+)"
);

# Affected version
# 4.3.x < 4.3.13.2
# 4.4.x < 4.4.14.1
cut_off = NULL;
fixed_ver = NULL;

if (version =~ "^4\.3\.")
{
  cut_off   = '4.3.0';
  fixed_ver = '4.3.13.2';
}
else if (version =~ "^4\.4\.")
{
  cut_off   = '4.4.0';
  fixed_ver = '4.4.14.1';
}
else
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
}

if (
  ver_compare(ver:version, fix:cut_off, regexes:re) >= 0 &&
  ver_compare(ver:version, fix:fixed_ver, regexes:re) == -1
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_ver +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
