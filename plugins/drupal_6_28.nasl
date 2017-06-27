#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63691);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2013-0244", "CVE-2013-0245", "CVE-2013-0246");
  script_bugtraq_id(57437);
  script_osvdb_id(89305, 89306, 89307);

  script_name(english:"Drupal 6.x < 6.28 / 7.x < 7.19 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a version of Drupal that is 6.x prior
to 6.28 or 7.x prior to 7.19. It is, therefore, potentially affected
by multiple vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists due to
    properly sanitized user-supplied input to certain Drupal
    JavaScript functions when running older versions of
    jQuery. A remote attacker can exploit this to inject
    arbitrary HTML and script code into a user's browser to
    be executed within the security context of the affected
    site. (CVE-2013-0244)

  - An access bypass vulnerability exists in the Book module
    (Printer Friendly Version) that allows an authenticated,
    remote attacker to access the content of arbitrary
    nodes. (CVE-2013-0245)

  - The Image module in version 7.x is affected by an access
    bypass vulnerability that allows unauthorized access to
    image derivatives. (CVE-2013-0246)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2013-001");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.28 / 7.19 or later.  

Note that the XSS issue can be mitigated by upgrading jQuery to 1.6.3
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

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
loc = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  # 6.x < 6.28 are affected
  (version =~ "^6\.([0-9]|1[0-9]|2[0-7])($|[^0-9]+)") ||
  # 7.x < 7.19 are affected
  (version =~ "^7\.([0-9]|1[0-8])($|[^0-9]+)")
)
{
  set_kb_item(name:"www/" + port + "/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + loc +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.28 / 7.19' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, loc, version);
