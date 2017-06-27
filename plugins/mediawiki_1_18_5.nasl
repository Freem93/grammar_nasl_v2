#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62358);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/06/12 22:35:11 $");

  script_cve_id(
    "CVE-2012-4377",
    "CVE-2012-4378",
    "CVE-2012-4379",
    "CVE-2012-4380",
    "CVE-2012-4381",
    "CVE-2012-4382"
  );
  script_bugtraq_id(55370);
  script_osvdb_id(85085, 85103, 85104, 85105, 85106, 85107, 85108);

  script_name(english:"MediaWiki < 1.18.5 / 1.19.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MediaWiki.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the instance of MediaWiki running on
the remote host is affected by multiple security vulnerabilities :

  - A stored cross-site scripting (HTML injection)
    vulnerability exists because the application fails to
    sufficiently sanitize user-supplied input submitted to
    the 'File:' tag of a non-existing image through
    comments. (CVE-2012-4377)

  - Multiple DOM-based cross-site scripting vulnerabilities 
    exist because the application fails to sufficiently 
    sanitize user-supplied input to the 'uselang' parameter 
    and JavaScript gadgets on various language Wikipedias. 
    (CVE-2012-4378)

  - A cross-site request forgery (XSRF) vulnerability
    exists because the application fails to properly
    validate requests when X-Frame-Options headers are
    used. (CVE-2012-4379)

  - A security-bypass vulnerability exists because the
    application fails to prevent the account creation for IP
    addresses blocked with the 'GlobalBlocking' extension.
    (CVE-2012-4380)

  - A security-bypass vulnerability exists because the
    application fails to prevent the use of old passwords in
    the external authentication system for non-existing
    accounts. (CVE-2012-4381)

  - An information disclosure occurs when an admin attempts
    to block a user who has already been blocked. This
    discloses the block reason to the second admin,
    regardless of the admin's privileges. (CVE-2012-4382)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-August/000119.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62757e45");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.18#MediaWiki_1.18.5");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.19#MediaWiki_1.19.2");
  script_set_attribute(attribute:"solution", value:"Upgrade to MediaWiki version 1.18.5 / 1.19.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mediawiki:mediawiki");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("mediawiki_detect.nasl");
  script_require_keys("Settings/ParanoidReport", "installed_sw/MediaWiki", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "MediaWiki";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);
version = install['version'];
url = build_url(qs:install['path'], port:port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  version =~ "^1\.([0-9]|1[0-7])\." ||
  version =~ "^1\.18\.([0-4]([^0-9]|$)|5[^0-9])" ||
  version =~ "^1\.19\.([0-1]([^0-9]|$)|2[^0-9])"
)
{
  set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);
  set_kb_item(name:"www/"+port+"/XSS",  value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : 1.18.5 / 1.19.2' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
