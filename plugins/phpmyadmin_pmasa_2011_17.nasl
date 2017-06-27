#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59211);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2011-4107");
  script_bugtraq_id(50497);
  script_osvdb_id(76798);

  script_name(english:"phpMyAdmin simplexml_load_string() Function Information Disclosure (PMASA-2011-17)");
  script_summary(english:"Checks version of phpmyadmin");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP application that is affected by an
information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-identified version number, the phpMyAdmin
install hosted on the remote web server is affected by an
information disclosure vulnerability.

The vulnerability, which is in the simplexml_load_string function in 
the XML import plug-in (libraries/import/xml.php) in phpMyAdmin 3.3.x
before 3.3.10.5 and 3.4.x before 3.4.7.1, allows remote,
authenticated users to read arbitrary files via XML data containing
external entity references.");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-17.php"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to phpMyAdmin 3.3.10.5 / 3.4.7.1 or later or, apply the
appropriate patches referenced in the project's advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/phpMyAdmin", "Settings/ParanoidReport");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:"phpMyAdmin", port:port, exit_on_fail:TRUE);
dir = install['dir'];
version = install['ver'];
location = build_url(qs:dir, port:port);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "phpMyAdmin", location);

if (version =~ "^3(\.[34])?$")
  exit(1, "The version of phpMyAdmin located at "+ location +" ("+ version +") is not granular enough.");

if (
  # 3.3.x < 3.3.10.5
  version =~ "^3\.3\.([0-9]|10(\.[0-4]|$))($|[^0-9])" ||
  # 3.4.x < 3.4.7.1
  version =~ "^3\.4\.([0-6]|7(\.0|$))([^0-9]|$)"
)
{

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + location +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.3.10.5 / 3.4.7.1' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "phpMyAdmin", location, version);
