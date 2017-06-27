#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58965);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id(
    "CVE-2012-1578",
    "CVE-2012-1579",
    "CVE-2012-1580",
    "CVE-2012-1581",
    "CVE-2012-1582",
    "CVE-2012-4885"
  );
  script_bugtraq_id(52689);
  script_osvdb_id(80361, 80362, 80363, 80364, 80365, 85513);

  script_name(english:"MediaWiki < 1.17.3 / 1.18.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MediaWiki.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the instance of MediaWiki running on
the remote host is affected by multiple security vulnerabilities :

  - An attacker can block/unblock arbitrary users via cross-
    site request forgery attack (XSRF) against an authorized 
    user. (CVE-2012-1578)

  - Unauthorized users can disclose XSRF tokens, triggered
    by a failure of the 'user.tokens' module to restrict
    access. (CVE-2012-1579)

  - An attacker can specially craft a URL that, should the
    victim be tricked into following it, would execute
    arbitrary script code in the victim's browser.
    (CVE-2012-1580)

  - Due to a flaw in pseudo-random number generation,
    password reset tokens may be predictable.
    (CVE-2012-1581)

  - A cross-site scripting vulnerability exists because 
    MediaWiki does not validate input passed via the
    wikitext parser during page creation prior to returning
    it to the user. This allows the creation of a specially
    crafted URL that would execute arbitrary code in the
    user's browser. An attacker can also cause an infinite
    loop, leading to a denial of service. (CVE-2012-1582,
    CVE-2012-4885)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade MediaWiki to version 1.17.3 / 1.18.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
  # http://lists.wikimedia.org/pipermail/wikitech-l/2012-March/059230.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?541c3ffc");
  # http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-March/000109.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcaa1381");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mediawiki:mediawiki");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("mediawiki_detect.nasl");
  script_require_keys("Settings/ParanoidReport", "installed_sw/MediaWiki", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
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

function is_vulnerable(ver)
{
  return
    ver =~ "^1\.([0-9]|1[0-6])\." ||
    ver =~ "^1\.17\.([0-2](\D|$)|3\D)" ||
    ver =~ "^1\.18\.([0-1](\D|$)|2\D)";
}

# If vulnerable...
if (is_vulnerable(ver:version))
{
  set_kb_item(name:"www/" + port + "/XSRF", value:TRUE);
  set_kb_item(name:"www/" + port + "/XSS",  value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : 1.17.3 / 1.18.2' +
      '\n';
    security_warning(port:port, extra:report);
  } 
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
