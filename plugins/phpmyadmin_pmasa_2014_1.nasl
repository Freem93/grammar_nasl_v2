#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72714);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_cve_id("CVE-2014-1879");
  script_bugtraq_id(65717);
  script_osvdb_id(103356);

  script_name(english:"phpMyAdmin 3.x >= 3.3.1 / 4.x < 4.1.7 import.php XSS (PMASA-2014-1)");
  script_summary(english:"Checks version of phpMyAdmin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-identified version number, the phpMyAdmin install
hosted on the remote web server is 3.x later than 3.3.1 or 4.x prior to
4.1.7.  It is, therefore, affected by a cross-site scripting
vulnerability because the 'import.php' script does not properly sanitize
the filenames of imported files.");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-1.php");
  # https://github.com/phpmyadmin/phpmyadmin/commit/968d5d5f486820bfa30af046f063b9f23304e14a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33815603");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to phpMyAdmin 4.1.7 or later, or apply the patch from
the referenced link.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/26");

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

if (version =~ "^3(\.\d+)?$" || version =~ "^4(\.\d+)?$") exit(1, "The version of phpMyAdmin located at "+ url +" ("+ version +") is not granular enough.");

# Affected version
# 3.x >= 3.3.1
# 4.x < 4.1.7

fixed_ver = "4.1.7";

re = make_array(-2, "-beta(\d+)",
                -1, "-rc(\d+)");

if (
  (version =~ "^3\.3\.1-(rc|beta)\d+") ||
  (version =~ "^3\." && ver_compare(ver:version, fix:"3.3.1", regexes:re) >= 0) ||
  (version =~ "^4\." && ver_compare(ver:version, fix:fixed_ver, regexes:re) == -1)
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
