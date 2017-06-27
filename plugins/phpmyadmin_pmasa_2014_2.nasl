#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76277);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_cve_id("CVE-2014-4348");
  script_bugtraq_id(68201);
  script_osvdb_id(108309);

  script_name(english:"phpMyAdmin 4.2.x < 4.2.4 Recent/Favorite Table Navigation Multiple XSS (PMASA-2014-2)");
  script_summary(english:"Checks version of phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin install
hosted on the remote web server is 4.2.x prior to 4.2.4. It is,
therefore, affected by multiple cross-site scripting vulnerabilities.

The flaws exist due to user input not being validated in a crafted
database or table name after being added to the favorite or recent
table list. This could allow a remote authenticated attacker, with a
specially crafted request, to execute arbitrary script code within the
browser / server trust relationship.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-2.php");
  # https://github.com/phpmyadmin/phpmyadmin/commit/cb7c703c03f656debcea2a16468bd53660fc888e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a9085da");
  # https://github.com/phpmyadmin/phpmyadmin/commit/d18a2dd9faad7e0e96df799b59e16ef587afb838
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03053a6c");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to phpMyAdmin 4.2.4 or later, or apply the patch from the
referenced link.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/27");

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

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:"phpMyAdmin", port:port, exit_on_fail:TRUE);
dir = install['dir'];
url = build_url(qs:dir, port:port);

version = install['ver'];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "phpMyAdmin", url);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ "^4(\.\d+)?$") audit(AUDIT_VER_NOT_GRANULAR, "phpMyAdmin", port, version);

# Affected version
# 4.2.0 < 4.2.4

fixed_ver = "4.2.4";

re = make_array(-2, "-beta(\d+)",
                -1, "-rc(\d+)");

if (
  ver_compare(ver:version, fix:"4.2.0", regexes:re) >= 0 &&
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
