#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78738);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_cve_id("CVE-2014-8326");
  script_bugtraq_id(70731);
  script_osvdb_id(113602, 113603);

  script_name(english:"phpMyAdmin 4.0.x < 4.0.10.5 / 4.1.x < 4.1.14.6 / 4.2.x < 4.2.10.1 Multiple XSS (PMASA-2014-12)");
  script_summary(english:"Checks the version of phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin
application hosted on the remote web server is 4.0.x prior to
4.0.10.5, 4.1.x prior to 4.1.14.6, or 4.2.x prior to 4.2.10.1. It is,
therefore, affected by the following cross-site scripting
vulnerabilities :

  - The 'libraries/DatabaseInterface.class.php' script does
    not validate input to database and table names in SQL
    debug output before returning it to users.

  - The 'js/server_status_monitor.js' script does not
    validate input to executed queries before they are
    viewed or analyzed.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-12.php");
  # https://github.com/phpmyadmin/phpmyadmin/commit/bd68c54d1beeef79d237e8bfda44690834012a76
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b0b4c16");
  # https://github.com/phpmyadmin/phpmyadmin/commit/7b8962dede7631298c81e2c1cd267b81f1e08a8c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58e25324");
  # https://github.com/phpmyadmin/phpmyadmin/commit/f989e2a94cb75158d33330e0e29f9b54ce3d7c07
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6d9753b");
  # https://github.com/phpmyadmin/phpmyadmin/commit/0092f608d37d0ce7acea30ec9e7e995ef1a6e06c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d81aa0b");
  # https://github.com/phpmyadmin/phpmyadmin/commit/57594febab385cd8fa3bc2c4511caa014d09485a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0465513c");
  # https://github.com/phpmyadmin/phpmyadmin/commit/a150ea1df477fcc9a79bbdf3f26b40d9e333bcf1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63d6d946");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin 4.0.10.5 / 4.1.14.6 / 4.2.10.1 or later, or
apply the patches from the referenced links.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

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
# 4.0.x < 4.0.10.5
# 4.1.x < 4.1.14.6
# 4.2.x < 4.2.10.1
cut_off = NULL;
fixed_ver = NULL;

if (version =~ "^4\.0\.")
{
  cut_off   = '4.0.0';
  fixed_ver = '4.0.10.5';
}
else if (version =~ "^4\.1\.")
{
  cut_off   = '4.1.0';
  fixed_ver = '4.1.14.6';
}
else if (version =~ "^4\.2\.")
{
  cut_off   = '4.2.0';
  fixed_ver = '4.2.10.1';
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
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
