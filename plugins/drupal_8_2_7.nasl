#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97942);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/28 13:38:34 $");

  script_cve_id(
    "CVE-2017-6377",
    "CVE-2017-6379",
    "CVE-2017-6381"
  );
  script_bugtraq_id(96919);
  script_osvdb_id(
    153877,
    153878,
    153879
  );

  script_name(english:"Drupal 8.x < 8.2.7 Multiple Vulnerabilities (SA-2017-001)");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Drupal running on the remote web server is 8.x prior to
8.2.7. It is, therefore, affected by the multiple vulnerabilities :

  - A security bypass vulnerability exists in the editor
    module due to a failure to properly check access
    restrictions when adding private files with a configured
    text editor (e.g. CKEDITOR). An unauthenticated, remote
    attacker can exploit this to bypass access restrictions
    and disclose arbitrary files. (CVE-2017-6377)

  - A cross-site request forgery (XSRF) vulnerability exists
    as HTTP requests do not require multiple steps, explicit
    confirmation, or a unique token when performing certain
    sensitive actions. An unauthenticated, remote attacker
    can exploit this, by convincing a user to follow a
    specially crafted link, to cause the user to disable
    some blocks on sites or perform additional unintended
    actions. (CVE-2017-6379)

  - An unspecified flaw exists in the PHPUnit component that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. Note that this vulnerability may only
    impact versions prior to 8.2.2. (CVE-2017-6381)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-2017-001");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.2.7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 8.2.7 or later. Additionally, as a
workaround for CVE-2017-6381, remove the /vendor/phpunit directory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
url = build_url(qs:dir, port:port);
fix = NULL;

if (version == "8") audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

if (ver_compare(ver:version, minver:"8.0", fix:"8.2.7", strict:FALSE) < 0)
  fix = "8.2.7";

if (isnull(fix))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);

security_report_v4(
    port:port,
    severity:SECURITY_WARNING,
    xsrf:TRUE,
    extra:
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n'
);
