#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76915);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/11 21:07:50 $");

  script_cve_id(
    "CVE-2014-4954",
    "CVE-2014-4955",
    "CVE-2014-4986",
    "CVE-2014-4987"
  );
  script_bugtraq_id(68798, 68799, 68803, 68804);
  script_osvdb_id(109350, 109351, 109352, 109353, 109354);

  script_name(english:"phpMyAdmin 4.0.x < 4.0.10.1 / 4.1.x < 4.1.14.2 / 4.2.x < 4.2.6 Multiple Vulnerabilities (PMASA-2014-4 - PMASA-2014-7)");
  script_summary(english:"Checks the version of phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin install
hosted on the remote web server is 4.0.x prior to 4.0.10.1, 4.1.x
prior to 4.1.14.2, or 4.2.x prior to 4.2.6. It is, therefore, affected
by the following vulnerabilities :

  - The 'TABLE_COMMENT' parameter input is not being
    validated in the script 'libraries/structure.lib.php'
    and could allow cross-site scripting attacks. Note that
    this issue affects the 4.2.x branch. (CVE-2014-4954)

  - The 'trigger' parameter input is not being validated in
    the script 'libraries/rte/rte_list.lib.php' and could
    allow cross-site scripting attacks. (CVE-2014-4955)

  - The 'table' and 'curr_column_name' parameter inputs are
    not being validated in the scripts 'js/functions.js'
    and 'js/tbl_structure.js' respectively and could allow
    cross-site scripting attacks. (CVE-2014-4986)

  - The script 'server_user_groups.php' contains an error
    that could allow a remote attacker to obtain the MySQL
    user list and possibly make changes to the application
    display. Note this issue only affects the 4.1.x and
    4.2.x branches. (CVE-2014-4987)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://sourceforge.net/p/phpmyadmin/news/2014/07/phpmyadmin-40101-41142-and-426-are-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?545bac7a");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-4.php");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-5.php");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-6.php");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-7.php");
  # https://github.com/phpmyadmin/phpmyadmin/commit/57475371a5b515c83bfc1bb2efcdf3ddb14787ed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91815216");
  # https://github.com/phpmyadmin/phpmyadmin/commit/10014d4dc596b9e3a491bf04f3e708cf1887d5e1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8cdbf2d1");
  # https://github.com/phpmyadmin/phpmyadmin/commit/511c596b175889b8e6b9c423e352ca64fa20af2b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1aafba98");
  # https://github.com/phpmyadmin/phpmyadmin/commit/1b5592435617fa1b9dd68e2dc263de64c69fdc8a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67967469");
  # https://github.com/phpmyadmin/phpmyadmin/commit/29a1f56495a7d1d98da31a614f23c0819a606a4d
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3bfc267");
  # https://github.com/phpmyadmin/phpmyadmin/commit/cd5697027a2ee7e1f7d7000b23be6051cdb0516c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97997036");
  # https://github.com/phpmyadmin/phpmyadmin/commit/a92753bd65e1f8b72c46ed3dda6c362628e0daf7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79fdaa0b");
  # https://github.com/phpmyadmin/phpmyadmin/commit/395265e9937beb21134626c01a21f44b28e712e5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7abe0a00");
  # https://github.com/phpmyadmin/phpmyadmin/commit/45550b8cff06ad128129020762f9b53d125a6934
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55cf9587");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to phpMyAdmin 4.0.10.1 / 4.1.14.2 / 4.2.6 or later, or
apply the patches from the referenced links.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/phpMyAdmin", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:"phpMyAdmin", port:port, exit_on_fail:TRUE);
dir = install['dir'];
url = build_url(qs:dir, port:port);
version = install['ver'];

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "phpMyAdmin", url);
if (version =~ "^4(\.[012])?$") audit(AUDIT_VER_NOT_GRANULAR, "phpMyAdmin", port, version);
if (version !~ "^4\.[012][^0-9]") audit(AUDIT_WEB_APP_NOT_INST, "phpMyAdmin 4.0.x / 4.1.x / 4.2.x", port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

re = make_array(
  -2, "-beta(\d+)",
  -1, "-rc(\d+)"
);

# Affected version
# 4.0.x < 4.0.10.1
# 4.1.x < 4.1.14.2
# 4.2.x < 4.2.6

if (version =~ "^4\.0\.")
{
  cut_off   = '4.0.0';
  fixed_ver = '4.0.10.1';
}

if (version =~ "^4\.1\.")
{
  cut_off   = '4.1.0';
  fixed_ver = '4.1.14.2';
}

if (version =~ "^4\.2\.")
{
  cut_off   = '4.2.0';
  fixed_ver = '4.2.6';
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
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "phpMyAdmin", url, version);
