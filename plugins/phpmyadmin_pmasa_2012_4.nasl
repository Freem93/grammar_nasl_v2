#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61659);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2012-4345", "CVE-2012-4579");
  script_bugtraq_id(55068, 73624);
  script_osvdb_id(
    84708,
    84868,
    84869,
    84870,
    84871,
    84872,
    84873
  );

  script_name(english:"phpMyAdmin 3.4.x < 3.4.11.1 / 3.5.x < 3.5.2.2 Multiple XSS (PMASA-2012-4)");
  script_summary(english:"Checks the version of phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-identified version number, the phpMyAdmin
install hosted on the remote web server is affected by multiple
cross-site scripting vulnerabilities. Using a crafted table name, it's
possible to produce the issue with the following pages / conditions :

  - The Database Structure page by creating a table with a 
    crafted name or using the Empty and Drop links of the 
    crafted table name.

  - The Table Operations page of a crafted table by using
    the 'Empty the table (TRUNCATE)' and 'Delete the table
    (DROP)' links.

  - The Triggers page of a database containing tables with
    a crafted name when opening the 'Add Trigger' pop-up.

  - When creating a trigger for a table with a crafted name
    with an invalid definition.

  - When visualizing GIS data having a crafted label name.

Note that version 3.4.x is only affected by the issues on the Database
Structure page, while versions 3.5.x are affected by all the issues
listed.");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2012-4.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin 3.4.11.1 / 3.5.2.2 or later. Alternatively,
apply the patch referenced in the vendor security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/24");

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

if (version =~ "^3(\.4)?$" || version =~ "^3(\.5)?$")
  exit(1, "The version of phpMyAdmin located at "+ location +" ("+ version +") is not granular enough.");

if (
  # 3.4.x < 3.4.11.1
  version =~ "^3\.4\.([0-9]|10(\.[0-9]+|$)|11(\.0|$))($|[^0-9])" ||
  # 3.5.x < 3.5.2.2
  version =~ "^3\.5\.([0-1]|2(\.[0-1]|$))([^0-9]|$)"
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + location +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.4.11.1 / 3.5.2.2' +
      '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "phpMyAdmin", location, version);
