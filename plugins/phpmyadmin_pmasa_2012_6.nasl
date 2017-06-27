#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62663);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2012-5339", "CVE-2012-5368");
  script_bugtraq_id(55925, 55939);
  script_osvdb_id(86170, 86680, 86681, 86682);

  script_name(english:"phpMyAdmin 3.5.x < 3.5.3 Multiple Vulnerabilities (PMASA-2012-6 - PMASA-2012-7)");
  script_summary(english:"Checks version of phpMyAdmin");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-identified version number, the phpMyAdmin 3.5.x
install hosted on the remote web server is earlier than 3.5.3 and is,
therefore, affected by multiple vulnerabilities :
 
  - When creating or modifying a trigger, event, or
    procedure with a crafted name, it is possible for a user
    to trigger a cross-site scripting (XSS) attack.

  - A man-in-the-middle (MITM) attack is possible when
    fetching the version information from a non-SSL site.
    To display information about the current phpMyAdmin
    version, a piece of JavaScript is fetched from the
    phpmyadmin.net website in non-SSL mode. A MITM attack 
    could modify this script on the wire."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2012-6.php");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2012-7.php");
  script_set_attribute(
    attribute:"solution",
    value:
"Either upgrade to phpMyAdmin 3.5.3 or later, or apply the patches from
the referenced links."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/phpMyAdmin", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:"phpMyAdmin", port:port, exit_on_fail:TRUE);
dir = install['dir'];
version = install['ver'];
location = build_url(qs:dir, port:port);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "phpMyAdmin", location);

if (version =~ "^3(\.5)?$")
  exit(1, "The version of phpMyAdmin located at "+ location +" ("+ version +") is not granular enough.");

if (
  # 3.5.x < 3.5.3
  # ensure to flag 3.5.3-rc1 as vulnerable but not 3.5.3
  version =~ "^3\.5\.([0-2]([^0-9]|$)|3-rc1)"
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + location +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.5.3' +
      '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "phpMyAdmin", location, version);
