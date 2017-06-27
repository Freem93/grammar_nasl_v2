#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76405);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/06/12 22:35:11 $");

  script_osvdb_id(108471);

  script_name(english:"MediaWiki < 1.19.17 / 1.21.11 / 1.22.8 / 1.23.1 External SVG Resource");
  script_summary(english:"Checks MediaWiki version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by an
input validation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the instance of MediaWiki running on
the remote host is affected by an error related to SVG file handling
that allows unintended usage of external resources.

Nessus has not tested for this issue but has instead relied on the
application's self-reported version number.");
  # http://lists.wikimedia.org/pipermail/mediawiki-announce/2014-June/000155.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f358c8e6");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.19#MediaWiki_1.19.17");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.21#MediaWiki_1.21.11");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.22#MediaWiki_1.22.8");
  script_set_attribute(attribute:"see_also", value:"http://www.mediawiki.org/wiki/Release_notes/1.23#MediaWiki_1.23.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki version 1.19.17 / 1.22.8 / 1.23.1 or later.

Note that, while 1.21.11 addresses this vulnerability, the 1.21 branch
reached end-of-life in June 2014.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/08");

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
  version =~ "^1\.19\.(\d|1[0-6])([^0-9]|$)" ||
  version =~ "^1\.21\.(\d|10)([^0-9]|$)"     ||
  version =~ "^1\.22\.[0-7]([^0-9]|$)"       ||
  version =~ "^1\.23\.0([^0-9]|$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : 1.19.17 / 1.21.11 / 1.22.8 / 1.23.1' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
