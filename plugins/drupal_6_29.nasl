#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71144);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2013-6385", "CVE-2013-6386");
  script_bugtraq_id(63837, 63840, 63845, 63849);
  script_osvdb_id(100031, 100032, 100036, 100037);

  script_name(english:"Drupal 6.x < 6.29 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a version of Drupal that is 6.x prior
to 6.29. It is, therefore, potentially affected by multiple
vulnerabilities :

  - An error exists related to the HTML form API and
    validation callbacks as used by third-party modules
    that could allow an attacker to bypass the cross-site
    request forgery protections. (CVE-2013-6385)

  - An error exists in the function mt_rand(), used for
    pseudorandom number generation, that could allow an
    attacker to obtain seeds through brute-force attacks.
    (CVE-2013-6386)

  - On Apache web servers containing application code that
    does not protect against the execution of uploaded
    files, it may be possible to upload arbitrary PHP files
    and cause them to execute. Note that if the intended
    remediation is an upgrade and the server is an Apache
    server, a manual fix is required. (BID 63845)

  - An error exists in the function drupal_valid_token()
    that could allow it to validate invalid tokens, thus
    allowing a security bypass. Note that an attacker must
    be able to cause a non-string value to be passed to the
    function for a successful attack. (BID 63849)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2013-003");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/drupal-6.29-release-notes");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 6.29 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

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
url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = '6.29';
if (version =~ "^6\.([0-9]|1[0-9]|2[0-8])($|[^0-9]+)")
{
  set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
