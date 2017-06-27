#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57346);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:30:35 $");

  script_cve_id(
    "CVE-2011-2505",
    "CVE-2011-2506",
    "CVE-2011-2507",
    "CVE-2011-2508"
  );
  script_bugtraq_id(48563);
  script_osvdb_id(73611, 73612, 73613, 73614);
  script_xref(name:"EDB-ID", value:"17510");
  script_xref(name:"EDB-ID", value:"17514");

  script_name(english:"phpMyAdmin 3.3.x / 3.4.x < 3.3.10.2 / 3.4.3.1 Multiple Vulnerabilities (PMASA-2011-5 - PMASA-2011-8)");
  script_summary(english:"Checks version of phpMyAdmin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of phpMyAdmin - 3.3.x less than
3.3.10.2 or 3.4.x less than 3.4.3.1 - that is affected by multiple
vulnerabilities :

  - An error in the file
    'libraries/auth/swekey/swekey.auth.lib.php' allows an
    attacker to modify the 'SESSION' superglobal array.
    (CVE-2011-2505)

  - An error in the file
    'setup/lib/ConfigGenerator.class.php' does not properly
    handle PHP comment-closing delimiters. This can allow
    an attacker inject static code via a modified 'SESSION'
    superglobal array. (CVE-2011-2506)

  - An error in the file
    'libraries/server_synchronize.lib.php' does not properly
    call the 'preg_replace' function. This can allow an
    attacker to execute arbitrary code via a modified
    'SESSION' superglobal array. (CVE-2011-2507)

  - An local file inclusion error exists in the
    'PMA_displayTableBody' function in the file
    'libraries/display_tbl.lib.php' that can allow an
    attacker to obtain sensitive information or execute
    code in file already present on the host.
    (CVE-2011-2508)");

  script_set_attribute(attribute:"see_also", value:"http://ha.xxor.se/2011/07/phpmyadmin-3x-multiple-remote-code.html");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-5.php");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-6.php");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-7.php");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-8.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to phpMyAdmin version 3.3.10.2 / 3.4.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Phpmyadmin 3.x RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/phpMyAdmin", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

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
  # 3.3.x < 3.3.10.2
  version =~ "^3\.3\.([0-9]|10(\.[01]|$))($|[^0-9])" ||
  # 3.4.x < 3.4.3.1
  version =~ "^3\.4\.([0-2]|3(\.0|$))([^0-9]|$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.3.10.2 / 3.4.3.1' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The phpMyAdmin "+version+" install at "+build_url(port:port,qs:dir)+" is not affected.");
