#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55023);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2011-1940", "CVE-2011-1941");
  script_bugtraq_id(47945, 47943);
  script_osvdb_id(72842, 72843);
  script_xref(name:"Secunia", value:"44641");

  script_name(english:"phpMyAdmin < 3.3.10.1 / 3.4.1 Multiple Vulnerabilities (PMASA-2011-03 - PMASA-2011-04");
  script_summary(english:"Checks version of phpMyAdmin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of phpMyAdmin - 3.3.x less than
3.3.10.1 or 3.4.x less than 3.4.1 - that is affected by multiple
vulnerabilities:

  - The scripts 'tbl_links.php' and 'tbl-tracking' fail to
    filter input to the 'table' and 'db' parameters.  An
    attacker may be able to exploit this issue to inject
    arbitrary HTML and script code into a user's browser,
    to be executed within the security context of the
    affected application, resulting in the theft of session
    cookies and a compromise of a user's account.
    (Issue #2011-03)

  - For versions 3.4.x < 3.4.1, the script 'url.php' fails
    to validate input to the 'url' parameter before
    redirecting to a specified location. (Issue #2011-04)");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-3.php");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-4.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to phpMyAdmin version 3.3.10.1 / 3.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpMyAdmin", "www/PHP", "Settings/ParanoidReport");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

port    = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:"phpMyAdmin", port:port, exit_on_fail:TRUE);

dir         = install['dir'];
install_url = build_url(port:port,qs:dir);
version     = install['ver'];

if (version == UNKNOWN_VER)
  exit(1, "The version of phpMyAdmin located at "+install_url+" could not be determined.");

if (version =~ "^3(\.[34])?$")
  exit(1, "The version of phpMyAdmin located at "+install_url+" ("+version+") is not granular enough.");

if (
  # 3.3.x < 3.3.10.1
  version =~ "^3\.3\.([0-9]|10(\.0|$))($|[^0-9])" ||
  # 3.4.x < 3.4.1
  version =~ "^3\.4\.(0|[^0-9.]|$)"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.3.10.1 / 3.4.1' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The phpMyAdmin "+version+" install at "+build_url(port:port,qs:dir)+" is not affected.");
