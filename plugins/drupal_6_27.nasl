#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63324);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2012-5651", "CVE-2012-5652", "CVE-2012-5653");
  script_bugtraq_id(56993);
  script_osvdb_id(88527, 88528, 88529);

  script_name(english:"Drupal 6.x < 6.27 / 7.x < 7.18 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a version of Drupal that is 6.x prior
to 6.27 or 7.x prior to 7.18. It is, therefore, potentially affected
by multiple vulnerabilities :

  - An access bypass vulnerability exists that allows search
    results to improperly display information about blocked
    users. (CVE-2012-5651)

  - Version 6.x is affected by an information disclosure
    vulnerability that allows information about uploaded
    files to be displayed in RSS feeds and search results
    for users that do not have the 'view uploaded files'
    permission. (CVE-2012-5652)

  - An arbitrary code execution vulnerability exists due to
    a failure to properly verify user-uploaded files. A
    remote, authenticated attacker, using a specially named
    PHP file, can bypass input validation checks, and the
    uploaded file can then be executed with the privileges
    of the web server user. (CVE-2012-5653)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2012-004");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 6.27 / 7.18 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "installed_sw/Drupal", "Settings/ParanoidReport");
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
loc = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  # 6.x < 6.27 are affected
  (version =~ "^6\.([0-9]|1[0-9]|2[0-6])($|[^0-9]+)") ||
  # 7.x < 7.18 are affected
  (version =~ "^7\.([0-9]|1[0-7])($|[^0-9]+)")
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + loc +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.27 / 7.18' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, loc, version);
