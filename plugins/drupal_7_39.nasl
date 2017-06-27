#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85653);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/11/01 04:40:10 $");

  script_cve_id(
    "CVE-2015-6658",
    "CVE-2015-6659",
    "CVE-2015-6660",
    "CVE-2015-6661",
    "CVE-2015-6665"
  );
  script_osvdb_id(
    126505,
    126506,
    126507,
    126508,
    126509
  );

  script_name(english:"Drupal 7.x < 7.39 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a version of Drupal that is 7.x prior
to 7.39. It is, therefore, potentially affected by the following
vulnerabilities :

  - A cross-site scripting vulnerability exists in the
    autocomplete functionality due to improper validation of
    input passed via requested URLs. An authenticated,
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary script code.
    (CVE-2015-6658)

  - A SQL injection vulnerability exists in the SQL comment
    filtering system due to improper sanitization of
    user-supplied input before using it in SQL queries. An
    authenticated, remote attacker can exploit this to
    inject SQL queries, resulting in the manipulation or
    disclosure of arbitrary data. (CVE-2015-6659)

  - A cross-site request forgery vulnerability exists in the
    form API due to improper validation of form tokens. An
    authenticated, remote attacker can exploit this, via a
    specially crafted link, to upload arbitrary files under
    another user's account. (CVE-2015-6660)

  - An information disclosure vulnerability exists that
    allows a remote, authenticated user to view the titles
    of nodes that they do not have access to.
    (CVE-2015-6661)

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input when invoking
    Drupal.ajax() on whitelisted HTML elements. A remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code.
    (CVE-2015-6665)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2015-003");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/drupal-7.39-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.39 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

if (version =~ "^7\.([0-9]|[1-2][0-9]|3[0-8])($|[^0-9]+)")
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.39' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
