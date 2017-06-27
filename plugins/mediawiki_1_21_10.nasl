#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76148);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/06/12 22:35:11 $");

  script_cve_id("CVE-2014-3966");
  script_bugtraq_id(67787);
  script_osvdb_id(107528);

  script_name(english:"MediaWiki < 1.19.16 / 1.21.10 / 1.22.7 'Special:PasswordReset' XSS");
  script_summary(english:"Checks the MediaWiki version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the instance of MediaWiki running on
the remote host is affected by a cross-site scripting vulnerability.
An input-validation flaw exists related to 'Special:PasswordReset'.
This allows a remote attacker to execute arbitrary code within the
server and browser trust relationship.

Nessus has not tested for this issue but has instead relied on the
application's self-reported version number.");
  # http://lists.wikimedia.org/pipermail/mediawiki-announce/2014-May/000151.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7475f07e");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=65501");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.19");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.21");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.22");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki version 1.19.16 / 1.22.7 or later.

Note that, although version 1.21.10 also addresses the vulnerability,
the 1.21.x release branch was obsoleted in June 2014.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mediawiki:mediawiki");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

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

# Affected
# 1.19.x < 1.19.16
# 1.21.x < 1.21.10
# 1.22.x < 1.22.7
if (
  version =~ "^1\.19\.(\d|1[0-5])([^0-9]|$)" ||
  version =~ "^1\.21\.\d([^0-9]|$)" ||
  version =~ "^1\.22\.[0-6]([^0-9]|$)"
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : 1.19.16 / 1.21.10 / 1.22.7' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
