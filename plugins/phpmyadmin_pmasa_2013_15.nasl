#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69184);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/11 21:07:50 $");

  script_cve_id(
    "CVE-2013-4995",
    "CVE-2013-4996",
    "CVE-2013-4997",
    "CVE-2013-4998",
    "CVE-2013-4999",
    "CVE-2013-5000",
    "CVE-2013-5001",
    "CVE-2013-5002",
    "CVE-2013-5003"
  );
  script_bugtraq_id(
    61510,
    61511,
    61512,
    61513,
    61515,
    61516,
    61919,
    61921,
    61923
  );
  script_osvdb_id(
    95787,
    95788,
    95789,
    95790,
    95791,
    95792,
    95793,
    95794,
    95795,
    95796,
    95797,
    95798
  );

  script_name(english:"phpMyAdmin 3.5.x < 3.5.8.2 / 4.0.x < 4.0.4.2 Multiple Vulnerabilities (PMASA-2013-8 - PMASA-2013-15");
  script_summary(english:"Checks version of phpMyAdmin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-identified version number, the phpMyAdmin install
hosted on the remote web server is 3.5.x earlier than 3.5.8.2 or 4.0.x
earlier than 4.0.4.2.  It is, therefore, affected by the following
vulnerabilities :

 - Numerous input validation errors exist that could lead
   to cross-site scripting attacks related to
   'version.json', text to link transformations, schema
   export, SQL queries, setup, chart display, process list,
   and the logo link. Note that the link transformation
   issue, PMASA-2013-13 (CVE-2013-5001), only affects the
   4.0.x branch. (CVE-2013-4995, CVE-2013-4996,
   CVE-2013-4997, CVE-2013-5001, CVE-2013-5002)

  - Errors exist that could allow full installation path
    disclosure via error messages. This information could
    be used in further attacks. (CVE-2013-4998,
    CVE-2013-4999, CVE-2013-5000)

  - Errors in the files 'schema_export.php' and
    'pmd_pdf.php' could allow SQL injection attacks.
    (CVE-2013-5003)");
  # http://sourceforge.net/p/phpmyadmin/news/2013/07/phpmyadmin-3582-and-4042-are-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ee11125");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-8.php");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-9.php");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-11.php");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-12.php");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-13.php");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-14.php");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-15.php");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to phpMyAdmin 3.5.8.2, 4.0.4.2 or later, or apply the
patches from the referenced links.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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
location = build_url(qs:dir, port:port);

version = install['ver'];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "phpMyAdmin", location);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ "^3(\.5)?$" || version =~ "^4(\.0)?$") exit(1, "The version of phpMyAdmin located at "+ location +" ("+ version +") is not granular enough.");

# 3.5.x < 3.5.8.2
# 4.0.x < 4.0.4.2
if (
  version =~ "^3\.5\.([0-7]|8($|-rc\d)|8.[0-1])([^0-9]|$)" ||
  version =~ "^4\.0\.([0-3]|4($|-rc\d)|4.[0-1])([^0-9]|$)"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + location +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.5.8.2 / 4.0.4.2' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "phpMyAdmin", location, version);
