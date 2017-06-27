#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69448);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/05/24 02:15:10 $");

  script_cve_id("CVE-2013-5029");
  script_bugtraq_id(61804);
  script_osvdb_id(95999);

  script_name(english:"phpMyAdmin 3.5.x / 4.x < 4.0.5 'Header.class.php' Clickjacking Bypass (PMASA-2013-10)");
  script_summary(english:"Checks version of phpMyAdmin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by a
clickjacking vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-identified version number, the phpMyAdmin 3.5.x
or 4.x install hosted on the remote web server is earlier than 4.0.5
and, therefore, contains a flaw where the 'Header.class.php' script
does not properly sanitize input.  This could allow attackers to 
bypass the application's clickjacking protections.");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-10.php");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to phpMyAdmin 4.0.5 or later, or apply the patches
from the referenced link.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

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

if (version =~ "^4(\.0)?$") exit(1, "The version of phpMyAdmin located at "+ location +" ("+ version +") is not granular enough.");

# 3.5.x
# 4.0.0 < 4.0.5
if (
  version =~ "^3\.5($|[^0-9])" ||
  version =~ "^4\.0\.([0-4]|5-rc\d)([^0-9]|$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + location +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.0.5' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "phpMyAdmin", location, version);
