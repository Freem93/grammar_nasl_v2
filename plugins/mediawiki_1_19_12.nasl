#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72878);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/06/12 22:35:11 $");

  script_cve_id("CVE-2014-2242", "CVE-2014-2243", "CVE-2014-2244");
  script_bugtraq_id(65883, 65906, 65910);
  script_osvdb_id(103901, 103905, 103906);

  script_name(english:"MediaWiki < 1.19.12 / 1.21.6 / 1.22.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MediaWiki.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of
MediaWiki running on the remote host is affected by the following
vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists in the
    includes/upload/UploadBase.php script due to improper
    validation of user-supplied input during the uploading
    of an SVG namespace. This allows a remote attacker to
    create a specially crafted request to execute arbitrary
    script code in a user's browser session within the trust
    relationship between the browser and server.
    (CVE-2014-2242)

  - A flaw exists in the includes/User.php script in the
    theloadFromSession() function where the validation of
    user tokens is terminated upon encountering the first
    incorrect character. This allows a remote attacker to
    gain access to session tokens using a brute force timing
    attack. (CVE-2014-2243)

  - A cross-site scripting (XSS) vulnerability exists in the
    includes/api/ApiFormatBase.php script in the
    formatHTML() function due to improper validation of
    user-supplied input when handling links appended to
    api.php. This allows a context-dependent attacker to
    create a specially crafted request to execute arbitrary
    code in a user's browser session within the trust
    relationship between the browser and server.
    (CVE-2014-2244)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://lists.wikimedia.org/pipermail/mediawiki-announce/2014-February/000141.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?641338dd");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.19");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.21");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.22");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=60771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=61346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=61362");
  script_set_attribute(attribute:"solution", value:"Upgrade to MediaWiki version 1.19.12 / 1.21.6 / 1.22.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/07");

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
  version =~ "^1\.19\.([0-9]|1[01])([^0-9]|$)" ||
  version =~ "^1\.21\.[0-5]([^0-9]|$)" ||
  version =~ "^1\.22\.[0-2]([^0-9]|$)"
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : 1.19.12 / 1.21.6 / 1.22.3' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
