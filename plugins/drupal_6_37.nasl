#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85652);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/11/01 04:40:10 $");

  script_cve_id(
    "CVE-2015-6658",
    "CVE-2015-6660",
    "CVE-2015-6661"
  );
  script_osvdb_id(
    126506,
    126508,
    126509
  );

  script_name(english:"Drupal 6.x < 6.37 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a version of Drupal that is 6.x prior
to 6.37. It is, therefore, potentially affected by the following
vulnerabilities :

  - A cross-site scripting vulnerability exists in the
    autocomplete functionality due to improper validation of
    input passed via requested URLs. An authenticated,
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary script code.
    (CVE-2015-6658)

  - A cross-site request forgery vulnerability exists in the
    form API due to improper validation of form tokens. An
    authenticated, remote attacker can exploit this, via a
    specially crafted link, to upload arbitrary files under
    another user's account. (CVE-2015-6660)

  - An information disclosure vulnerability exists that
    allows a remote, authenticated user to view the titles
    of nodes that they do not have access to.
    (CVE-2015-6661)

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2015-003");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/drupal-6.37-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 6.37 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/26");

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

fix = '6.37';
if (version =~ "^6\.([0-9]|[12][0-9]|3[0-6])($|[^0-9]+)")
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

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
