#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78233);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_cve_id("CVE-2014-7217");
  script_bugtraq_id(70252);
  script_osvdb_id(112487, 112488);

  script_name(english:"phpMyAdmin 4.0.x < 4.0.10.4 / 4.1.x < 4.1.14.5 / 4.2.x < 4.2.9.1 'ENUM' Value XSS (PMASA-2014-11)");
  script_summary(english:"Checks the version of phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin
application hosted on the remote web server is 4.0.x prior to
4.0.10.4, 4.1.x prior to 4.1.14.5, or 4.2.x prior to 4.2.9.1. It is,
therefore, affected by an input validation error related to the 'ENUM'
value and the files 'libraries/TableSearch.class.php' and
'libraries/Util.class.php'. This issue could allow cross-site
scripting attacks.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-11.php");
  # 4.0.x patch
  # https://github.com/phpmyadmin/phpmyadmin/commit/c6c77589a5860f20b5fb335033389de50e1a9031
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d26560ae");
  # 4.1.x patch
  # https://github.com/phpmyadmin/phpmyadmin/commit/71ccbbc423bcfd14ba40174b3adcd9a0fafaa511
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a404b70");
  # 4.2.x patches
  # https://github.com/phpmyadmin/phpmyadmin/commit/c1a3f85fbd1a9569646e7cf1b791325ae82c7961
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68163849");
  # https://github.com/phpmyadmin/phpmyadmin/commit/304fb2b645b36a39e03b954fdbd567173ebe6448
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0a07dda");

  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin 4.0.10.4 / 4.1.14.5 / 4.2.9.1 or later, or apply
the patches from the referenced links.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_keys("www/PHP", "www/phpMyAdmin", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "phpMyAdmin";

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:appname, port:port, exit_on_fail:TRUE);
dir = install['dir'];
url = build_url(qs:dir, port:port);
version = install['ver'];

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, url);
if (version =~ "^4(\.[012])?$") audit(AUDIT_VER_NOT_GRANULAR, appname, port, version);
if (version !~ "^4\.[012][^0-9]") audit(AUDIT_WEB_APP_NOT_INST, appname + " 4.0.x / 4.1.x / 4.2.x", port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

re = make_array(
  -2, "-beta(\d+)",
  -1, "-rc(\d+)"
);

# Affected version
# 4.0.x < 4.0.10.4
# 4.1.x < 4.1.14.5
# 4.2.x < 4.2.9.1
cut_off = NULL;
fixed_ver = NULL;

if (version =~ "^4\.0\.")
{
  cut_off   = '4.0.0';
  fixed_ver = '4.0.10.4';
}

if (version =~ "^4\.1\.")
{
  cut_off   = '4.1.0';
  fixed_ver = '4.1.14.5';
}

if (version =~ "^4\.2\.")
{
  cut_off   = '4.2.0';
  fixed_ver = '4.2.9.1';
}

# The following should never happen at this
# point, but best to be safe and check anyway.
if (isnull(cut_off) || isnull(fixed_ver))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);

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
