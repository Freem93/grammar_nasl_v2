#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55993);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2011-3181");
  script_bugtraq_id(49306);
  script_osvdb_id(74781);

  script_name(english:"phpMyAdmin 3.3.x / 3.4.x < 3.3.10.4 / 3.4.4 XSS (PMASA-2011-13");
  script_summary(english:"Checks version of phpMyAdmin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of phpMyAdmin - 3.3.x less than
3.3.10.4 or 3.4.x less than 3.4.4 - that is affected by multiple
cross-site scripting vulnerabilities.

The data in the 'table', 'column', and 'index' variables of the script
'tbl_tracking.php' are not properly sanitized before being sent to the
browser.

These errors can allow an unauthenticated user to trick an
authenticated user into requesting a URL thereby injecting arbitrary
HTML or script code into the authenticated user's browser.

These errors can also allow an attacker who has access to the database
to create persistent strings of cross-site scripting code that will
inject arbitrary HTML or script code into an authenticated user's
browser at a later time.");

  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-13.php");
  script_set_attribute(attribute:"see_also", value:"http://fd.the-wildcat.de/pma_e36aa9e2e0.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to phpMyAdmin version 3.3.10.4 / 3.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

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
  # 3.3.x < 3.3.10.4
  version =~ "^3\.3\.([0-9]|10(\.[0-3]|$))($|[^0-9])" ||
  # 3.4.x < 3.4.4
  version =~ "^3\.4\.[0-3]([^0-9]|$)"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.3.10.4 / 3.4.4' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The phpMyAdmin "+version+" install at "+build_url(port:port,qs:dir)+" is not affected.");
