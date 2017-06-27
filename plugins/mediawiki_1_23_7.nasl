#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80121);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/06/12 22:35:12 $");

  script_cve_id("CVE-2014-9276", "CVE-2014-9277");
  script_bugtraq_id(71473);
  script_osvdb_id(115143, 115144, 115145, 115146);

  script_name(english:"MediaWiki < 1.19.22 / 1.22.14 / 1.23.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the MediaWiki version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the MediaWiki application running on
the remote host is affected by the following vulnerabilities :

  - An input validation error exists related to handling
    previews of wikitext that allows cross-site scripting
    attacks. (CVE-2014-9276)

  - An input validation error exists related to flash policy
    mangling, API clients, and 'format=php' that allows
    cross-site scripting. (CVE-2014-9277)

  - An error exists related to 'content model' editing that
    allows a remote, unprivileged attacker to modify a
    user's 'common.js' file. (Bug 70901)

  - An error exists related to deleting an entry. The
    'DELETED_ACTION' and the action 'revdeleted' allows
    information disclosure via log files. (Bug 72222)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://lists.wikimedia.org/pipermail/mediawiki-announce/2014-November/000170.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7796737d");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.19#MediaWiki_1.19.22");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.22#MediaWiki_1.22.14");
  script_set_attribute(attribute:"see_also", value:"http://www.mediawiki.org/wiki/Release_notes/1.23#MediaWiki_1.23.7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki version 1.19.22 / 1.22.14 / 1.23.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/19");

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
  version =~ "^1\.19\.(\d|1\d|2[01])([^0-9]|$)" ||
  version =~ "^1\.22\.(\d|1[0-3])([^0-9]|$)"  ||
  version =~ "^1\.23\.[0-6]([^0-9]|$)"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : 1.19.22 / 1.22.14 / 1.23.7' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
