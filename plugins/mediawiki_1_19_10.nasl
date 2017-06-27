#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72370);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/06/12 22:35:11 $");

  script_cve_id(
    "CVE-2013-4570",
    "CVE-2013-4571",
    "CVE-2013-4574",
    "CVE-2013-6451",
    "CVE-2013-6452",
    "CVE-2013-6453",
    "CVE-2013-6454",
    "CVE-2013-6455",
    "CVE-2013-6472",
    "CVE-2014-3454"
  );
  script_bugtraq_id(64966, 65003, 67522);
  script_osvdb_id(
    99943,
    102183,
    102251,
    102293,
    102296,
    102348,
    102448,
    102449,
    102493,
    102494,
    104409
  );

  script_name(english:"MediaWiki < 1.19.10 / 1.21.4 / 1.22.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MediaWiki.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the instance of MediaWiki running on
the remote host is affected by the following vulnerabilities :

  - Escape sequences are not properly sanitized when passed
    to the 'Sanitizer::checkCss' class, which allows a
    remote attacker to conduct cross-site scripting attacks.
    (CVE-2013-6451)

  - An input validation error exists in the
    'XmlTypeCheck.php' script in uploaded SVG files that
    contain external style sheets, which allows a remote
    attacker to conduct cross-site scripting attacks.
    (CVE-2013-6452)

  - Input validation by the checkSvgScriptCallback()
    function is bypassed in the 'UploadBase.php' script
    when an SVG file with invalid XML is uploaded. This
    can result in malicious code execution. (CVE-2013-6453)

  - An input validation error exists in the 'Sanitizer.php'
    script when input is submitted to the '-o-link'
    attribute, which allows cross-site scripting attacks in
    Opera 12. (CVE-2013-6454)

  - An information disclosure vulnerability exists in the
    log API, Enhanced Recent Changes feature, and users'
    watchlists that allows deleted log entries to be viewed.
    (CVE-2013-6472)

Additionally, the following extensions contain vulnerabilities but
are not enabled or installed by default (unless otherwise noted) :

  - The TimedMediaHandler extension is affected by a
    cross-site scripting vulnerability due to the lack of
    input validation of the 'data-videopayload' attribute
    in the 'mw.PopUpThumbVideo.js' script. (CVE-2013-4574)

  - The Scribuntu extension is affected by a NULL pointer
    dereference and buffer overflow flaw in the
    implementation of the 'luasandbox' PHP extension that
    can lead to a denial of service or arbitrary code
    execution. (CVE-2013-4570, CVE-2013-4571)

  - The CentralAuth extension is affected by an information
    disclosure vulnerability due to the insertion of a
    username into the page's DOM. (CVE-2013-6455)

  - The Semantic Forms extension is affected by a cross-site
    request forgery (XSRF) vulnerability due to the lack of
    token validation in the 'Special:CreateCategory' page.
    (CVE-2014-3454)

Note that Nessus has not tested for these issues but has instead
relied on the application's self-reported version number.");
  # http://lists.wikimedia.org/pipermail/mediawiki-announce/2014-January/000138.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c1aad04");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.19#MediaWiki_1.19.10");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.20#MediaWiki_1.21.4");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.22#MediaWiki_1.22.1");
  script_set_attribute(attribute:"solution", value:"Upgrade to MediaWiki version 1.19.10 / 1.21.4 / 1.22.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mediawiki:mediawiki");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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
  version =~ "^1\.19\.[0-9]([^0-9]|$)" ||
  version =~ "^1\.21\.[0-3]([^0-9]|$)" ||
  version =~ "^1\.22\.[0]([^0-9]|$)"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : 1.19.10 / 1.21.4 / 1.22.1' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
