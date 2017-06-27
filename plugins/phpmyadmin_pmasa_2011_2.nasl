#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59244);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2011-0987");
  script_bugtraq_id(46359);
  script_osvdb_id(70962);

  script_name(english:"phpMyAdmin 2.11.x / 3.3.x < 2.11.11.3 / 3.3.9.2 SQL Query Bookmarks Arbitrary SQL Query Execution (PMASA-2011-02)");
  script_summary(english:"Checks version of phpMyAdmin");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP application that could be abused to
execute SQL queries."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-identified version number, the phpMyAdmin
install hosted on the remote web server allows creation of bookmarked
SQL queries which could be unintentionally executed by other users. 

Note that successful exploitation of this vulnerability requires that
phpMyAdmin configuration storage is set up and enabled and that the
application's bookmarks feature is enabled."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-2.php");
  script_set_attribute(
    attribute:"solution",
    value:
"Either upgrade to phpMyAdmin 2.11.11.3 / 3.3.9.2 or later, or apply
the patch from the referenced link"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/23");

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

if (version =~ "^2(\.11)?$" || version =~ "^3(\.3)?$")
  exit(1, "The version of phpMyAdmin located at "+ location +" ("+ version +") is not granular enough.");

if (
  # 2.11.x < 2.11.11.3
  version =~ "^2\.11\.([0-9]|1[0-1](\.[0-2]|$))($|[^0-9])" ||
  # 3.3.x < 3.3.9.2
  version =~ "^3\.3\.([0-8]|9(\.1|$))([^0-9]|$)"
)
{

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + location +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.11.11.3 / 3.3.9.2' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "phpMyAdmin", location, version);
