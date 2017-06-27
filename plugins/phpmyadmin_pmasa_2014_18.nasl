#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79797);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/11 21:07:50 $");

  script_cve_id("CVE-2014-9218", "CVE-2014-9219");
  script_bugtraq_id(71434, 71435);
  script_osvdb_id(115322, 115323);

  script_name(english:"phpMyAdmin 4.0.x < 4.0.10.7 / 4.1.x < 4.1.14.8 / 4.2.x < 4.2.13.1 Multiple Vulnerabilities (PMASA-2014-17 - PMASA-2014-18)");
  script_summary(english:"Checks the version of phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin
application hosted on the remote web server is 4.0.x prior to
4.0.10.7, 4.1.x prior to 4.1.14.8, or 4.2.x prior to 4.2.13.1. It is,
therefore, affected by the following vulnerabilities :

  - A flaw exists in handling overly long passwords. It is
    possible that a remote attacker can cause a denial of
    service by using a long password. (CVE-2014-9218)

  - A cross-site scripting flaw exists due to the improper
    validation of URLs when handling redirection. A remote
    attacker, by using a specially crafted request, could
    execute arbitrary script code within the trust
    relationship of the browser and server. Note that this
    applies only to versions 4.2.x prior to 4.2.13.1.
    (CVE-2014-9219)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-17.php");
  # https://github.com/phpmyadmin/phpmyadmin/commit/095729d81205f15f40d216d25917017da4c2fff8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?683380d0");
  # https://github.com/phpmyadmin/phpmyadmin/commit/62b2c918d26cc78d1763945e3d44d1a63294a819
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcfab292");
  # https://github.com/phpmyadmin/phpmyadmin/commit/1ac863c7573d12012374d5d41e5c7dc5505ea6e1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a847dfb");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-18.php");
  # https://github.com/phpmyadmin/phpmyadmin/commit/9b2479b7216dd91a6cc2f231c0fd6b85d457f6e2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb7a3b51");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin 4.0.10.7 / 4.1.14.8 / 4.2.13.1 or later, or
apply the patches referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

if (version =~ "^4(\.[012])?$") audit(AUDIT_VER_NOT_GRANULAR, appname, port, version);
if (version !~ "^4\.[012][^0-9]") audit(AUDIT_WEB_APP_NOT_INST, appname + " 4.0.x / 4.1.x / 4.2.x", port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

re = make_array(
  -2, "-beta(\d+)",
  -1, "-rc(\d+)"
);

# Affected version
# 4.0.x < 4.0.10.7
# 4.1.x < 4.1.14.8
# 4.2.x < 4.2.13.1
cut_off = NULL;
fixed_ver = NULL;

if (version =~ "^4\.0\.")
{
  cut_off   = '4.0.0';
  fixed_ver = '4.0.10.7';
}
else if (version =~ "^4\.1\.")
{
  cut_off   = '4.1.0';
  fixed_ver = '4.1.14.8';
}
else if (version =~ "^4\.2\.")
{
  cut_off   = '4.2.0';
  fixed_ver = '4.2.13.1';
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
  if (version =~ "^4\.2\.")
    set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

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
