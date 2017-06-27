#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65899);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/06/12 22:35:11 $");

  script_cve_id("CVE-2013-1816", "CVE-2013-1817", "CVE-2013-1818");
  script_bugtraq_id(58304, 58305, 58306);
  script_osvdb_id(90890, 90891, 90902);

  script_name(english:"MediaWiki 1.19.x < 1.19.4 / 1.20.x < 1.20.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MediaWiki.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the instance of MediaWiki running on
the remote host is affected by multiple security vulnerabilities :

  - A flaw exists related to certificate validation due to
    the server hostname not being verified to match a domain
    name in the Common Name (CN) or SubjectAltName of the
    X.509 certificate. This allows a man-in-the-middle
    attacker to spoof SSL services through the use of an
    arbitrary certificate. (CVE-2013-1816)

  - A flaw exists when unblocking a user via the API that
    leads to the disclosure of sensitive information.
    (CVE-2013-1817)

  - A flaw exists in version 1.20 in the
    'maintenance/mwdoc-filter.php' script that is triggered
    under certain server conditions. A remote attacker can
    exploit this to gain access to arbitrary files.
    (CVE-2013-1818)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
# http://lists.wikimedia.org/pipermail/mediawiki-announce/2013-March/000125.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4cdf5ec");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.19#MediaWiki_1.19.4");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.20#MediaWiki_1.20.3");
  script_set_attribute(attribute:"solution", value:"Upgrade to MediaWiki version 1.19.4 / 1.20.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mediawiki:mediawiki");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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
install_url = build_url(qs:install['path'], port:port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  version =~ "^1\.19\.[0-3]([^0-9]|$)" ||
  version =~ "^1\.20\.[0-2]([^0-9]|$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : 1.19.4 / 1.20.3' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
