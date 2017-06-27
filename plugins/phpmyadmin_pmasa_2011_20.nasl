
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57372);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_cve_id("CVE-2011-4780", "CVE-2011-4782");
  script_bugtraq_id(51166, 51226);
  script_osvdb_id(77983, 78036);

  script_name(english:"phpMyAdmin 3.4.x < 3.4.9 XSS (PMASA-2011-19 - PMASA-2011-20)");
  script_summary(english:"Checks version of phpMyAdmin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by two
cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of phpMyAdmin hosted on the remote web server is 3.4.x
less than 3.4.9 and thus is reportedly affected by two cross-site
scripting vulnerabilities :

  - The 'libraries/display_export.lib.php' script does not
    properly sanitize the '$_GET' array elements
    'limit_to', 'limit_from' and 'filename_template'
    before returning it to the client. (CVE-2011-4780)

  - The 'libraries/config/ConfigFile.class.php' script does
    not properly sanitize input in the '$host' parameter
    before returning it to the client. Note that this issue
    relates to the '/setup' directory and configuration of
    the application and should not be exploitable if the
    recommended installation steps have been performed.
    (CVE-2011-4782)");

  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-19.php");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-20.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to phpMyAdmin version 3.4.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

if (version == UNKNOWN_VER) exit(1, "The version of phpMyAdmin at "+install_url+" could not be determined.");
if (version =~ "^3(\.[4])?$") exit(1, "The version of phpMyAdmin at "+install_url+" ("+version+") is not granular enough.");

# 3.4.x < 3.4.9
if (version =~ "^3\.4\.[0-8]([^0-9]|$)")
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.4.9' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The phpMyAdmin "+version+" install at "+build_url(port:port,qs:dir)+" is not affected.");
