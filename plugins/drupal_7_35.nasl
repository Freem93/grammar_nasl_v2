#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81975);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/07/07 21:05:39 $");

  script_cve_id("CVE-2015-2559", "CVE-2015-2749", "CVE-2015-2750");
  script_bugtraq_id(73219);
  script_osvdb_id(119762, 119763);

  script_name(english:"Drupal 6.x < 6.35 / 7.x < 7.35 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a version of Drupal that is 6.x prior
to 6.35 or 7.x prior to 7.35. It is, therefore, potentially affected
by the following vulnerabilities :

  - An access bypass vulnerability exists in which password
    reset URLs can be forged. This allows a remote attacker
    to gain access to another user's account.
    (CVE-2015-2559)

  - An open redirect vulnerability exists which allows a
    remote attacker to craft a URL using the 'destination'
    parameter in order to trick users into being redirected
    to third-party sites. Additionally, several URL related
    API functions can be tricked into passing external URLs.
    (CVE-2015-2749, CVE-2015-2750)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2015-001");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/drupal-7.35-release-notes");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/drupal-6.35-release-notes");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 6.35 / 7.35 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
url = build_url(qs:dir, port:port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  version =~ "^7\.([0-9]|[1-2][0-9]|3[0-4])($|[^0-9]+)" ||
  version =~ "^6\.([0-9]|[1-2][0-9]|3[0-4])($|[^0-9]+)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.35 / 6.35' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
