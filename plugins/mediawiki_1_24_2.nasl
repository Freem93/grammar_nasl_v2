#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84164);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_cve_id(
    "CVE-2014-9714",
    "CVE-2015-2931",
    "CVE-2015-2932",
    "CVE-2015-2933",
    "CVE-2015-2934",
    "CVE-2015-2935",
    "CVE-2015-2936",
    "CVE-2015-2937",
    "CVE-2015-2938",
    "CVE-2015-2939",
    "CVE-2015-2940",
    "CVE-2015-2941",
    "CVE-2015-2942"
  );
  script_bugtraq_id(74061, 73477);
  script_osvdb_id(
    120238,
    120239,
    120240,
    120241,
    120242,
    120243,
    120244,
    120245,
    120246,
    120247,
    120273,
    120274,
    130893
  );

  script_name(english:"MediaWiki < 1.19.24 / 1.23.9 / 1.24.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the MediaWiki version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the MediaWiki application running on
the remote host is affected by the following vulnerabilities :

  - An input validation error exists related to handling
    API errors that allows reflected cross-site scripting
    attacks. (CVE-2014-9714, CVE-2015-2941)

  - An input validation error exists related to SVG file
    uploads that allows stored cross-site scripting attacks
    by bypassing a missing MIME type blacklist.
    (CVE-2015-2931)

  - An input validation error exists related to the handling
    of JavaScript used to animate elements in the
    'includes/upload/UploadBase.php' script that allows a
    remote attacker to bypass the blacklist filter.
    (CVE-2015-2932)

  - An input validation error exists in the
    'includes/Html.php' script that allows stored cross-site
    scripting attacks. (CVE-2015-2933)

  - A flaw in the 'includes/libs/XmlTypeCheck.php' script
    allows a remote attacker to bypass the SVG filter by
    encoding SVG entities. (CVE-2015-2934)

  - A flaw in the 'includes/upload/UploadBase.php' script
    allows a remote attacker to bypass the SVG filter and
    de-anonymize the wiki readers. This issue exists due to
    an incomplete fix for CVE-2014-7199. (CVE-2015-2935)

  - A denial of service vulnerability exists due to a flaw
    in the handling of hashing large PBKDF2 passwords.
    (CVE-2015-2936)

  - A denial of service vulnerability exists due to an XML
    external entity injection (XXE) flaw that is triggered
    by the parsing of crafted XML data. (CVE-2015-2937)

  - An input validation error exists related to the
    user-supplied custom JavaScript that allows stored
    cross-site scripting attacks. (CVE-2015-2938)

  - An input validation error exists related to the
    Scribunto extension that allows stored cross-site
    scripting attacks. (CVE-2015-2939)

  - A flaw in the CheckUser extension allows cross-site
    request forgery attacks due to a flaw in which user
    rights are not properly checked. (CVE-2015-2940)

  - A denial of service vulnerability exists due to an
    XML external entity (XXE) injection flaw triggered by
    the parsing of crafted XML data in SVG or XMP files.
    (CVE-2015-2942)

  - A cross-site scripting vulnerability exists due to
    improper validation of input encoded entities in SVG
    files. An unauthenticated, remote attacker can exploit
    this, via a specially crafted request, to execute
    arbitrary script code in a user's browser session.
    (VulnDB 130893)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://lists.wikimedia.org/pipermail/mediawiki-announce/2015-March/000175.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfc5045c");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.19#MediaWiki_1.19.24");
  script_set_attribute(attribute:"see_also", value:"http://www.mediawiki.org/wiki/Release_notes/1.23#MediaWiki_1.23.9");
  script_set_attribute(attribute:"see_also", value:"http://www.mediawiki.org/wiki/Release_notes/1.24#MediaWiki_1.24.2");
  script_set_attribute(attribute:"see_also", value:"https://blogs.securiteam.com/index.php/archives/2669");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki version 1.19.24 / 1.23.9 / 1.24.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mediawiki:mediawiki");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
  version =~ "^1\.19\.(\d|1\d|2[0-3])([^0-9]|$)" ||
  version =~ "^1\.23\.[0-8]([^0-9]|$)" ||
  version =~ "^1\.24\.[01]([^0-9]|$)"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : 1.19.24 / 1.23.9 / 1.24.2' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
