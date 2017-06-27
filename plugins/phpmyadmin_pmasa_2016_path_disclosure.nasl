#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90428);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/29 19:06:13 $");

  script_cve_id("CVE-2016-2038", "CVE-2016-2042", "CVE-2016-2044");
  script_bugtraq_id(82075, 82097, 82104);
  script_osvdb_id(133793);

  script_name(english:"phpMyAdmin Multiple Path Disclosure Vulnerabilities (PMASA-2016-1, PMASA-2016-6, PMASA-2016-8)");
  script_summary(english:"Tests for path disclosure.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple path disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The phpMyAdmin application hosted on the remote web server is affected
by multiple path disclosure vulnerabilities in multiple scripts. An
unauthenticated, remote attacker can exploit these vulnerabilities,
via a specially crafted request, to disclose the full path of the
directory where phpMyAdmin is installed.

Note that phpMyAdmin is also reportedly affected by multiple
cross-site scripting and cross-site request forgery vulnerabilities;
however, Nessus has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-1/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-6/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-8/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 4.0.10.13 / 4.4.15.3 / 4.5.4 or later.
Alternatively, apply the patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "installed_sw/phpMyAdmin");

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

install = get_single_install(
  app_name : appname,
  port     : port
);

dir = install['path'];
url = build_url(qs:dir, port:port);
version = install['version'];

if (!empty_or_null(version) && verson =~ "^4\.(4|5)")
{
  if (version =~ "^4\.4\.")
  {
    files = make_array(
      "/libraries/phpseclib/Crypt/Rijndael.php", "(Fatal error: Class '(.*)Base)",
      "/libraries/phpseclib/Crypt/AES.php", "(Fatal error: Class '(.*)Rijndael)"
    );
  }
  if (version =~ "^4\.5\.")
  {
    files = make_array(
      "/libraries/sql-parser/autoload.php", "(Fatal error</b>:(\s)*Class '.*ClassLoader' not found)"
    );
  }
}
else
  files = make_array(
    "/setup/lib/common.inc.php", "(Call to undefined function PMA_fatalError\(\))",
    "/libraries/phpseclib/Crypt/Rijndael.php", "(Fatal error: Class '(.*)Base)",
    "/libraries/phpseclib/Crypt/AES.php", "(Fatal error: Class '(.*)Rijndael)",
    "/libraries/sql-parser/autoload.php", "(Fatal error</b>:(\s)*Class '.*ClassLoader' not found)"
  );

vuln = FALSE;
foreach file (keys(files))
{
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + file,
    exit_on_fail : TRUE
  );

  matches = eregmatch(
    pattern : files[file],
    string  : res[2],
    icase   : TRUE
  );
  if (!empty_or_null(matches))
  {
    vuln = TRUE;
    exploit = build_url(qs:dir + file, port:port);
    break;
  }
}
if (!vuln)
audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url);

security_report_v4(
  port     : port,
  severity : SECURITY_WARNING,
  generic  : TRUE,
  request  : make_list(exploit),
  output   : chomp(res[2])
);
exit(0);
