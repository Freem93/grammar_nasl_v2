#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77305);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_cve_id("CVE-2014-5273", "CVE-2014-5274");
  script_bugtraq_id(69268, 69269);
  script_osvdb_id(
    110139,
    110140,
    110148,
    110149,
    110150
  );

  script_name(english:"phpMyAdmin 4.0.x < 4.0.10.2 / 4.1.x < 4.1.14.3 / 4.2.x < 4.2.7.1 Multiple XSS Vulnerabilities (PMASA-2014-8 - PMASA-2014-9)");
  script_summary(english:"Checks the version of phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin
application hosted on the remote web server is 4.0.x prior to
4.0.10.2, 4.1.x prior to 4.1.14.3, or 4.2.x prior to 4.2.7.1. It is,
therefore, affected by the following vulnerabilities :

  - Multiple cross-site scripting vulnerabilities exist in
    the browser table, ENUM editor, monitor, query charts,
    and table relations pages. (CVE-2014-5273)

  - A flaw exists in the view operation page that allows a
    cross-site scripting attack. Note that this does not
    affect the 4.0.x releases. (CVE-2014-5274)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-8.php");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-9.php");
  # https://github.com/phpmyadmin/phpmyadmin/commit/647c9d12e33a6b64e1c3ff7487f72696bdf2dccb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fea869a4");
  # https://github.com/phpmyadmin/phpmyadmin/commit/2c45d7caa614afd71dbe3d0f7270f51ce5569614
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e1c0339");
  # https://github.com/phpmyadmin/phpmyadmin/commit/cd9f302bf7f91a160fe7080f9a612019ef847f1c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b49d1fce");
  # https://github.com/phpmyadmin/phpmyadmin/commit/90ddeecf60fc029608b972e490b735f3a65ed0cb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?274b0651");
  # https://github.com/phpmyadmin/phpmyadmin/commit/3ffc967fb60cf2910cc2f571017e977558c67821
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cec3b0ca");
  # https://github.com/phpmyadmin/phpmyadmin/commit/0cd293f5e13aa245e4a57b8d373597cc0e421b6f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6efd2e6");

  script_set_attribute(attribute:"solution", value:
"Either upgrade to phpMyAdmin 4.0.10.2 / 4.1.14.3 / 4.2.7.1 or later,
or apply the patches from the referenced links.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

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
# 4.0.x < 4.0.10.2
# 4.1.x < 4.1.14.3
# 4.2.x < 4.2.7.1

if (version =~ "^4\.0\.")
{
  cut_off   = '4.0.0';
  fixed_ver = '4.0.10.2';
}

if (version =~ "^4\.1\.")
{
  cut_off   = '4.1.0';
  fixed_ver = '4.1.14.3';
}

if (version =~ "^4\.2\.")
{
  cut_off   = '4.2.0';
  fixed_ver = '4.2.7.1';
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
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "phpMyAdmin", url, version);
