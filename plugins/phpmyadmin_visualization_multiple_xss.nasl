#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66203);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/14 20:12:25 $");

  script_cve_id("CVE-2013-1937");
  script_bugtraq_id(58962);
  script_osvdb_id(92201);

  script_name(english:"phpMyAdmin 3.5.x < 3.5.8 tbl_gis_visualization.php Multiple XSS");
  script_summary(english:"Checks version of phpMyAdmin");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP application that is affected by
multiple cross-site scripting vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-identified version number, the phpMyAdmin 3.5.x
install hosted on the remote web server is earlier than 3.5.8 and is,
therefore, affected by multiple cross-site scripting vulnerabilities. 
The flaw exists in the 'visualizationSettings[width]' and
'visualizationSettings[height]' parameters of the
'tls_gis_visualization.php' script.  An unauthenticated, remote
attacker, exploiting this flaw, could execute arbitrary script code in a
user's browser."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.waraxe.us/advisory-102.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Either upgrade to phpMyAdmin 3.5.8 or later, or apply the patches from
the referenced link."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:"phpMyAdmin", port:port, exit_on_fail:TRUE);
dir = install['dir'];
location = build_url(qs:dir, port:port);

version = install['ver'];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "phpMyAdmin", location);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ "^3(\.5)?$")
  exit(1, "The version of phpMyAdmin located at "+ location +" ("+ version +") is not granular enough.");

if (
  # 3.5.x < 3.5.8
  version =~ "^3\.5\.[0-7]([^0-9]|$)"
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + location +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.5.8' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "phpMyAdmin", location, version);
