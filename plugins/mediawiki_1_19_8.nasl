#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70293);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/06/12 22:35:11 $");

  script_cve_id(
    "CVE-2013-4301",
    "CVE-2013-4302",
    "CVE-2013-4303",
    "CVE-2013-4304",
    "CVE-2013-4305",
    "CVE-2013-4306",
    "CVE-2013-4307",
    "CVE-2013-4308"
  );
  script_bugtraq_id(
    62194,
    62201,
    62202,
    62203,
    62210,
    62215,
    62218,
    62434
  );
  script_osvdb_id(
    96906,
    96907,
    96908,
    96909,
    96910,
    96911,
    96912,
    96913
  );

  script_name(english:"MediaWiki < 1.19.8 / 1.20.7 / 1.21.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MediaWiki.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the instance of MediaWiki running on
the remote host is affected by the following vulnerabilities :

  - The full installation path is disclosed in an error
    message when an invalid language is specified in the
    ResourceLoader. (CVE-2013-4301)

  - Multiple cross-site request forgery vulnerabilities
    exist in the API modules accessed through JSONP.
    (CVE-2013-4302)

  - A cross-site scripting vulnerability exists because
    input submitted to the property name is not properly
    sanitized. (CVE-2013-4303)

Additionally, the following extensions contain vulnerabilities but
are not enabled or installed by default (unless otherwise noted) :

  - Authentication can be bypassed in the CentralAuth
    extension by manipulating the 'centralauth_User' cookie.
    (CVE-2013-4304)

  - The SyntaxHighlight GeSHi extension is affected by a
    cross-site scripting vulnerability because user input is
    not properly sanitized when submitted to the
    'example.php' script. This extension is installed but
    not enabled by default on MediaWiki 1.21.x.
    (CVE-2013-4305)

  - The CheckUser extension is affected by a cross-site
    request forgery vulnerability because it does not
    properly validate HTTP requests. (CVE-2013-4306)

  - The Wikibase extension is affected by a cross-site
    scripting vulnerability because it does not properly
    escape the labels in the 'In other languages' section of 
    entity view. (CVE-2013-4307)

  - The LiquidThreads extensions is affected by a cross-site
    scripting vulnerability because it does not properly
    sanitize user input submitted to the LQT thread subject.
    (CVE-2013-4308)

Note that Nessus has not tested for these issues but has instead
relied on the application's self-reported version number.");
  # http://lists.wikimedia.org/pipermail/mediawiki-announce/2013-September/000133.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c39fbdab");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.19#MediaWiki_1.19.8");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.20#MediaWiki_1.20.7");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.21#MediaWiki_1.21.2");
  script_set_attribute(attribute:"solution", value:"Upgrade to MediaWiki version 1.19.8 / 1.20.7 / 1.21.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/03");

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
  version =~ "^1\.19\.[0-7]([^0-9]|$)" ||
  version =~ "^1\.20\.[0-6]([^0-9]|$)" ||
  version =~ "^1\.21\.[0-1]([^0-9]|$)"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : 1.19.8 / 1.20.7 / 1.21.2' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
