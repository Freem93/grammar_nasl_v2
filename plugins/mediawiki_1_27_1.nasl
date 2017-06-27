#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93195);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id(
    "CVE-2016-6331",
    "CVE-2016-6332",
    "CVE-2016-6333",
    "CVE-2016-6334",
    "CVE-2016-6335",
    "CVE-2016-6336",
    "CVE-2016-6337"
  );
  script_osvdb_id(
    143393,
    143394,
    143395,
    143396,
    143397,
    143398,
    143399,
    143400
  );

  script_name(english:"MediaWiki 1.23.x < 1.23.15 / 1.26.x < 1.26.4 / 1.27.x < 1.27.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the MediaWiki version.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the MediaWiki application running on
the remote web server is 1.23.x prior to 1.23.15, 1.26.x prior to
1.26.4, or 1.27.x prior to 1.27.1. It is, therefore, affected by the
following vulnerabilities :

  - An information disclosure vulnerability exists in the
    ApiParse.php script due to improper checking of read
    permissions when loading page content. An
    unauthenticated, remote attacker can exploit this to
    disclose sensitive information. (CVE-2016-6331)

  - A security bypass vulnerability exists due to a failure
    to timeout a user's session after it has been blocked.
    An authenticated, remote attacker can exploit this to
    bypass block features. (CVE-2016-6332)

  - A cross-site request forgery vulnerability (XSRF) exists
    in the OutputPage.php script due to a failure to require
    multiple steps, explicit confirmation, or a unique token
    when performing certain sensitive actions. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to follow a specially crafted link, to
    perform arbitrary edits to CSS content. (CVE-2016-6333 /
    VulnDB 143393)

  - A cross-site scripting (XSS) vulnerability exists in the
    Html.php script due to improper validation of
    user-supplied input when handling improper inline style
    blocks via the CSS user subpage preview feature. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2016-6333 /
    VulnDB 143396)

  - A cross-site scripting (XSS) vulnerability exists in the
    Parser.php script due to improper validation of input to
    unclosed internal links. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2016-6334)

  - A flaw exists in the ApiParse.php script due to head
    items not being properly generated in the context of a
    title. An unauthenticated, remote attacker can exploit
    this to have an unspecified impact. (CVE-2016-6335)

  - A flaw exists in the LocalFile.php script that allows an
    authenticated, remote attacker to bypass suppressed
    viewing restrictions by deleting a file and then
    undeleting a specific revision of it. (CVE-2016-6336)

  - A security bypass vulnerability exists in the User.php
    script due to improper handling of extension hook
    functions. An unauthenticated, remote attacker can
    exploit this to bypass permission restrictions. Note
    that this vulnerability affects 1.27.x only.
    (CVE-2016-6337)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
# https://lists.wikimedia.org/pipermail/mediawiki-announce/2016-August/000195.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b9ed785");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.23#MediaWiki_1.23.15");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.26#MediaWiki_1.26.4");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.27#MediaWiki_1.27.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki version 1.23.15 / 1.26.4 / 1.27.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mediawiki:mediawiki");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mediawiki_detect.nasl");
  script_require_keys("Settings/ParanoidReport", "installed_sw/MediaWiki");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

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

if (
  version =~ "^1\.23\.([0-9]|1[0-4])([^0-9]|$)" ||
  version =~ "^1\.26\.[0-3]([^0-9]|$)" ||
  version =~ "^1\.27\.0([^0-9]|$)"
)
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + version +
    '\n  Fixed versions    : 1.23.15 / 1.26.4 / 1.27.1' + '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report, xss:TRUE, xsrf:TRUE);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
