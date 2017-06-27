#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81818);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2015-2206");
  script_bugtraq_id(72949);
  script_osvdb_id(119236);

  script_name(english:"phpMyAdmin 4.0.x < 4.0.10.9 / 4.2.x < 4.2.13.2 / 4.3.x < 4.3.11.1 Information Disclosure Vulnerability (PMASA-2015-1)");
  script_summary(english:"Checks the version of phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin
application hosted on the remote web server is 4.0.x prior to
4.0.10.9, 4.2.x prior to 4.2.13.2, or 4.3.x prior to 4.3.11.1. It is,
therefore, affected by an information disclosure vulnerability due to
the length of compressed HTTPS responses not being hidden. This allows
a remote attacker, using a series of crafted requests, to obtain the
CSRF token via a BREACH attack.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2015-1.php");
  # https://github.com/phpmyadmin/phpmyadmin/commit/b2f1e895038a5700bf8e81fb9a5da36cbdea0eeb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4cc2198");
  # https://github.com/phpmyadmin/phpmyadmin/commit/d0f109dfe3b345094d7ceb49df0dbb68efc032ed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11d0e38d");
  # https://github.com/phpmyadmin/phpmyadmin/commit/e1a68ad02c5b1a516b3787ce114ef6a6be004630
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b01e679");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin 4.0.10.9 / 4.2.13.2 / 4.3.11.1 or later, or
apply the patches referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

port = get_http_port(default:80, php:TRUE);

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
dir = install['path'];
url = build_url(qs:dir, port:port);
version = install['version'];

if (version =~ "^4(\.[023])?$") audit(AUDIT_VER_NOT_GRANULAR, appname, port, version);
if (version !~ "^4\.[023][^0-9]") audit(AUDIT_WEB_APP_NOT_INST, appname + " 4.0.x / 4.2.x / 4.3.x", port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

re = make_array(
  -2, "-beta(\d+)",
  -1, "-rc(\d+)"
);

# Affected version
# 4.0.x < 4.0.10.9
# 4.2.x < 4.2.13.2
# 4.3.x < 4.3.11.1
cut_off = NULL;
fixed_ver = NULL;

if (version =~ "^4\.0\.")
{
  cut_off   = '4.0.0';
  fixed_ver = '4.0.10.9';
}
else if (version =~ "^4\.2\.")
{
  cut_off   = '4.2.0';
  fixed_ver = '4.2.13.2';
}
else if (version =~ "^4\.3\.")
{
  cut_off   = '4.3.0';
  fixed_ver = '4.3.11.1';
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
