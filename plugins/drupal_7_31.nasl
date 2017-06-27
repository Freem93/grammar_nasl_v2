#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77186);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2014-5265", "CVE-2014-5266");
  script_bugtraq_id(69146);
  script_osvdb_id(109871, 109883);

  script_name(english:"Drupal 6.x < 6.33 / 7.x < 7.31 XML-RPC DoS");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a version of Drupal that is 6.x prior
to 6.33 or 7.x prior to 7.31. It is, therefore, potentially affected
by multiple denial of service vulnerabilities :

  - The XML-RPC library in Drupal allows entity declarations
    without considering recursion during entity expansion.
    A remote attacker, using a crafted XML document with a
    large number of nested entity references, can cause a
    denial of service by consuming available memory and CPU
    resources. (CVE-2014-5265)

  - The XML-RPC library in Drupal does not limit the number
    of elements in an XML document. A remote attacker, via
    a large document, could cause a denial of service by CPU
    consumption. (CVE-2014-5266)

  - An XML injection flaw exists in 'xmlrpc.php' due to the
    parser accepting XML internal entities from untrusted
    sources. A remote attacker, via specially crafted XML
    data, could exploit this to cause a denial of service.
    This vulnerability also exists within the Drupal OpenID
    module.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2014-004");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/drupal-7.31-release-notes");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/drupal-6.33-release-notes");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 6.33 / 7.31 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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

fix = NULL;

if (version =~ "^6\.([0-9]|[1-2][0-9]|3[0-2])($|[^0-9]+)") fix = '6.33';
else if (version =~ "^7\.([0-9]|[1-2][0-9]|30)($|[^0-9]+)") fix = '7.31';

if (fix)
{
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
