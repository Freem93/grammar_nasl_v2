#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73568);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/28 23:32:04 $");

  script_name(english:"MediaWiki Unsupported Version Detection");
  script_summary(english:"Checks for unsupported MediaWiki versions.");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of MediaWiki is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, an installation of
MediaWiki on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.mediawiki.org/wiki/Version_lifecycle");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of MediaWiki that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mediawiki:mediawiki");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

latest = '1.29.x / 1.28.x / 1.27.x / 1.23.x';

# key - regex to match unsupported versions
# value - link to statement that the corresponding versions are no longer supported.
#         this can be NULL for cases where we can't find an official statement
unsupported_versions = make_array(
  '^1\\.26\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.26',
  '^1\\.25\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.25',
  '^1\\.24\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.24',
  '^1\\.22\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.22',  # also https://lists.wikimedia.org/pipermail/mediawiki-announce/2014-November/000171.html
  '^1\\.21\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.21',  # also http://lists.wikimedia.org/pipermail/mediawiki-announce/2014-June/000153.html
  '^1\\.20\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.20',
  '^1\\.19\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.19',
  '^1\\.18\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.18',
  '^1\\.17\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.17',
  '^1\\.16\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.16',
  '^1\\.15\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.15',
  '^1\\.14\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.14',
  '^1\\.13\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.13',
  '^1\\.12\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.12',
  '^1\\.11\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.11',
  '^1\\.10\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.10',
  '^1\\.9\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.9',
  '^1\\.8\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.8',
  '^1\\.7\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.7',
  '^1\\.6\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.6',
  '^1\\.5\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.5',
  '^1\\.4\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.4',
  '^1\\.3\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.3',
  '^1\\.2\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.2',
  '^1\\.1\\.', 'http://www.mediawiki.org/wiki/MediaWiki_1.1'
);

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

# See if the version is unsupported...
foreach ver_regex (keys(unsupported_versions))
{
  if (version =~ ver_regex)
  {
    set_kb_item(name:"www/mediawiki/Unsupported", value:version);

    register_unsupported_product(product_name:"MediaWiki",
                                 cpe_base:"mediawiki:mediawiki", version:version);

    url = unsupported_versions[ver_regex];
    eol_url = "http://www.mediawiki.org/wiki/Version_lifecycle";

    report +=
      '\n  Product            : ' + app +
      '\n  URL                : ' + install_url +
      '\n  Installed version  : ' + version +
      '\n  Latest version     : ' + latest +
      '\n  End of support URL : ' + eol_url;

    if (!isnull(url))
      report += '\n  Additional info    : ' + url;

    report += '\n';

    break;
  }
}

# ...then report on any that were found
if (isnull(report)) exit(0, "The "+app+" install at " + install_url + " is still supported.");

if (report_verbosity > 0) security_hole(port:port, extra:report);
else security_hole(port);
