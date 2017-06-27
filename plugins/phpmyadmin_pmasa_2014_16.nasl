#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79599);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/11 21:07:50 $");

  script_cve_id(
    "CVE-2014-8958",
    "CVE-2014-8959",
    "CVE-2014-8960",
    "CVE-2014-8961"
  );
  script_bugtraq_id(71243, 71244, 71245, 71247);
  script_osvdb_id(114968, 114969, 114970, 114971, 114972, 114973, 114974);

  script_name(english:"phpMyAdmin 4.0.x < 4.0.10.6 / 4.1.x < 4.1.14.7 / 4.2.x < 4.2.12 Multiple Vulnerabilities (PMASA-2014-13 - PMASA-2014-16)");
  script_summary(english:"Checks the version of phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin
application hosted on the remote web server is 4.0.x prior to
4.0.10.6, 4.1.x prior to 4.1.14.7, or 4.2.x prior to 4.2.12. It is,
therefore, affected by the following vulnerabilities :

  - A cross-site scripting vulnerability in the zoom search
    page due to improper validation of input when handling
    an ENUM value before returning it to the user. A remote
    attacker, with a specially crafted request, could
    potentially execute arbitrary script code within the
    browser / server trust relationship. (CVE-2014-8958)

  - A cross-site scripting vulnerability in the home page
    due to improper validation of input when handling a font
    size before returning it to the user. A remote attacker,
    with a specially crafted request, could potentially
    execute arbitrary script code within the browser /
    server trust relationship. (CVE-2014-8958)

  - A cross-site scripting vulnerability in the print view
    page due to improper validation of input when handling
    an ENUM value before returning it to the user. A remote
    attacker, with a specially crafted request, could
    potentially execute arbitrary script code within the
    browser / server trust relationship. (CVE-2014-8958)

  - A cross-site scripting vulnerability in the table browse
    page due to improper validation of input when handling
    database, table, and column names before returning them
    to the user. A remote attacker, with a specially crafted
    request, could potentially execute arbitrary script code
    within the browser / server trust relationship.
    (CVE-2014-8958)

  - A local file inclusion vulnerability in the GIS editor
    feature due to improperly validation of a parameter used
    to specify the geometry type. This could allow a remote,
    authenticated attacker to include arbitrary files from
    the host, allowing disclosure of the file contents or
    the execution of scripts on the host. (CVE-2014-8959)

  - A cross-site scripting vulnerability in the error
    reporting page due to improper validation of filenames
    before returning them to the user. This could allow a
    remote attacker, with a specially crafted request, to
    potentially execute arbitrary script code within the
    browser / server trust relationship. (CVE-2014-8960)

  - An information disclosure vulnerability in the error
    reporting feature due to improper validation of
    user-supplied input. This could allow a remote,
    authenticated attacker to determine a file's line count.
    (CVE-2014-8961)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-13.php");
  # https://github.com/phpmyadmin/phpmyadmin/commit/d32da348c4de2379482a48661ce968a55eebe5c4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfe5cc06");
  # https://github.com/phpmyadmin/phpmyadmin/commit/1bc04ec95038f2356ad33752090001bf1c047208
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?94943b40");
  # https://github.com/phpmyadmin/phpmyadmin/commit/2a3b7393d1d5a8ba0543699df94a08a0f5728fe0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?866d3a60");
  # https://github.com/phpmyadmin/phpmyadmin/commit/2ffdbf2d7daa0b92541d8b754e2afac555d3ed21
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c5e2e33");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-14.php");
  # https://github.com/phpmyadmin/phpmyadmin/commit/80cd40b6687a6717860d345d6eb55bef2908e961
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b978eb70");
  # https://github.com/phpmyadmin/phpmyadmin/commit/59557b51362edc5eee024f3f2912a9d598e42763
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab0ccaa0");
  # https://github.com/phpmyadmin/phpmyadmin/commit/2e3f0b9457b3c8f78beb864120bd9d55617a11b5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?515d6830");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-15.php");
  # https://github.com/phpmyadmin/phpmyadmin/commit/9364e2eee5681681caf7205c0933bc18af11e233
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d2af6a3");
  # https://github.com/phpmyadmin/phpmyadmin/commit/c641ad40c37bc562226c8a25cce77a273a07756b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0200565");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-16.php");
  # https://github.com/phpmyadmin/phpmyadmin/commit/b99b6b6672ff2419f05b05740c80c7a23c1da994
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?41a9e040");
  # https://github.com/phpmyadmin/phpmyadmin/commit/da44dd4fd7432b915203e3e723a4534a01c12cd9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9193c577");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin 4.0.10.6 / 4.1.14.7 / 4.2.12 or later, or apply
the patches referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/27");

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
# 4.0.x < 4.0.10.6
# 4.1.x < 4.1.14.7
# 4.2.x < 4.2.12
cut_off = NULL;
fixed_ver = NULL;

if (version =~ "^4\.0\.")
{
  cut_off   = '4.0.0';
  fixed_ver = '4.0.10.6';
}
else if (version =~ "^4\.1\.")
{
  cut_off   = '4.1.0';
  fixed_ver = '4.1.14.7';
}
else if (version =~ "^4\.2\.")
{
  cut_off   = '4.2.0';
  fixed_ver = '4.2.12';
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
