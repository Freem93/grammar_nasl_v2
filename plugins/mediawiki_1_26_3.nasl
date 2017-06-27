#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91856);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_osvdb_id(
    139008,
    139009,
    139010,
    139011,
    139012,
    139013,
    139014,
    139015,
    139016,
    139017,
    139018,
    139019,
    139020,
    139097,
    139098
  );

  script_name(english:"MediaWiki 1.23.x < 1.23.14 / 1.25.x < 1.25.6 / 1.26.x < 1.26.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the MediaWiki version.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the MediaWiki application running on
the remote web server is 1.23.x prior to 1.23.14, 1.25.x prior to
1.25.6, or 1.26.x prior to 1.26.3. It is, therefore, affected by the
following vulnerabilities :

  - A flaw exists due to a failure to invalidate tokens from
    previous user sessions when starting a new session. An
    authenticated, remote attacker can exploit this to
    hijack another user's session. (VulnDB 139008)

  - A security bypass vulnerability exists in the
    SpecialUserlogin.php script due to improper handling of
    non-canonical usernames. An unauthenticated, remote
    attacker can exploit this to bypass login throttling.
    (VulnDB 139009)

  - A flaw exists due to a cross-domain policy regular
    expression (regexp) that is too narrow. An
    unauthenticated, remote attacker can exploit this to
    supply parameters within the tag and insert malicious
    data. (VulnDB 139010)

  - A denial of service vulnerability exists in the
    wfShellExec() function in the GlobalFunctions.php script
    due to missing string length limits for shell
    invocations. An authenticated, remote attacker can
    exploit this, via overly large commands, to crash the
    server. (VulnDB 139011)

  - A privilege escalation vulnerability exists in the
    RawAction.php script to improper management of sessions
    when handling cached data. An authenticated, remote
    attacker can exploit this to log in as another user and
    gain elevated privileges. (VulnDB 139012)

  - A security bypass vulnerability exists due to improper
    handling of specially-crafted, spoofed patrol links. An
    authenticated, remote attacker can exploit this to
    bypass restrictions and patrol arbitrary pages.
    (VulnDB 139013)

  - A flaw exists in the WebStart.php script due to
    insufficient checks against mbstring.func_overload. An
    unauthenticated, remote attacker can exploit this, using
    the predictable results, to conduct a brute-force
    attack. (VulnDB 139014)

  - A flaw exists when handling specially crafted requests
    that involve graphs. An unauthenticated, remote attacker
    can exploit this to disclose an edit token, allowing the
    attacker to then conduct a cross-site request forgery
    (XSRF) attack. (VulnDB 139015)

  - A denial of service vulnerability exists in the
    generateDiffBody() function in the DifferenceEngine.php
    script that allows an authenticated, remote attacker to
    cause multiple diffs to be concurrently loaded,
    resulting in a consumption of significant resources.
    (VulnDB 139016)

  - A cross-site redirection vulnerability exists due to a
    failure to securely use $wgExternalLinkTarget in the
    DefaultSettings.php script. An unauthenticated, remote
    attacker can exploit this, by convincing a user to
    follow a specially crafted link, to redirect a user to a
    malicious website. (VulnDB 139017)

  - A security bypass vulnerability exists in the
    ApiMove::execute() function in the ApiMove.php script
    due to a failure to properly rate limit the 'move API
    action'. An unauthenticated, remote attacker can exploit
    this to bypass intended rate restrictions on movement
    operations. (VulnDB 139018)

  - An authentication security bypass vulnerability exists
    in the MWOldPassword.php, MWSaltedPassword.php, and
    Pbkdf2Password.php scripts due to improper handling of
    unsupported hash algorithms. An unauthenticated, remote
    attacker can exploit this to bypass authentication
    mechanisms. Note that this vulnerability only affects
    versions 1.25.x and 1.26.x. (VulnDB 139019)

  - A flaw exists in the SpecialUserlogin.php script due to
    throttling password attempts for wiki accounts on a
    per-wiki basis rather than globally. An unauthenticated,
    remote attacker can exploit this to easily conduct 
    brute-force attacks. Note that this vulnerability only
    affects versions 1.23.x and 1.25.x. (VulnDB 139020)

  - A flaw exists in the includes/DefaultSettings.php script
    due to the 'pdkdf2' parameter not being hashed in a more
    secure manner, which can result in password hashes being
    less secure. A remote attacker can exploit this, using
    brute-force methods, to disclose the passwords.
    (VulnDB 139097)

  - A cross-site scripting (XSS) vulnerability exists in the
    includes/upload/UploadBase.php script within the
    UploadBase::checkSvgScriptCallback() function, when
    uploading SVG files, due to a failure to validate input
    before returning it to the user. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary script code in the
    user's browser session. (VulnDB 139098)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://lists.wikimedia.org/pipermail/mediawiki-announce/2016-May/000188.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?937cb355");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.23#MediaWiki_1.23.14");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.25#MediaWiki_1.25.6");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.26#MediaWiki_1.26.3");
  script_set_attribute(attribute:"see_also", value:"https://phabricator.wikimedia.org/T116030");
  script_set_attribute(attribute:"see_also", value:"https://phabricator.wikimedia.org/T123071");
  script_set_attribute(attribute:"see_also", value:"https://phabricator.wikimedia.org/T122653");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki version 1.23.14 / 1.25.6 / 1.26.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/27");

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
  version =~ "^1\.23\.([0-9]|1[0-3])([^0-9]|$)" ||
  version =~ "^1\.25\.[0-5]([^0-9]|$)" ||
  version =~ "^1\.26\.[0-2]([^0-9]|$)"
)
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + version +
    '\n  Fixed versions    : 1.23.14 / 1.25.6 / 1.26.3' +     '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report, xss:TRUE);
}

else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
