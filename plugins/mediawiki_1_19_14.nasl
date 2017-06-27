#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73305);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/06/12 22:35:11 $");

  script_cve_id("CVE-2014-2665");
  script_bugtraq_id(66600);
  script_osvdb_id(105088, 105520);

  script_name(english:"MediaWiki < 1.19.14 / 1.21.8 / 1.22.5 ChangePassword XSRF");
  script_summary(english:"Checks version of MediaWiki.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by a
cross-site request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the instance of MediaWiki running on
the remote host is affected by a cross-site request forgery
vulnerability.

A flaw exists with Special:ChangePassword within the
includes/specials/SpecialChangePassword.php script where HTTP requests
do not require explicit confirmation, a unique token, and/or multiple
steps performing sensitive actions. This allows a context-dependent
attacker to reset a user's password.

Nessus has not tested for this issue but has instead relied on the
application's self-reported version number.");
  # http://lists.wikimedia.org/pipermail/mediawiki-announce/2014-March/000145.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3acfa1d");
  # http://lists.wikimedia.org/pipermail/mediawiki-announce/2014-April/000147.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf7e4516");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.19");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.21");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.22");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=62497");
  # https://www.mediawiki.org/w/index.php?title=Thread:Project:Support_desk/Session_Hijacking_error_after_Update_1.19.14&lqt_oldid=54478
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7505c42f");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=62497#c14");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki version 1.19.15 / 1.21.8 / 1.22.5 or later.

Note that a fix for this issue was implemented with 1.19.14 but the
patch contains a mistake; users of 1.19.x should update to 1.19.15.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/02");

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

# Detecting for all previous versions.
if (
  version =~ "^1\.19\.([0-9]|1[0-3])([^0-9]|$)" ||
  version =~ "^1\.21\.[0-7]([^0-9]|$)" ||
  version =~ "^1\.22\.[0-4]([^0-9]|$)"
)
{
  set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : 1.19.15 / 1.21.8 / 1.22.5' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
