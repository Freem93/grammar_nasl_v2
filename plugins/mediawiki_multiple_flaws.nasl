#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(18035);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id(
    "CVE-2004-1405",
    "CVE-2004-2152",
    "CVE-2004-2185",
    "CVE-2004-2186",
    "CVE-2004-2187"
  );
  script_bugtraq_id(
    9057,
    10958,
    11302,
    11416,
    11480,
    11897,
    11985,
    12305,
    12444,
    12625
  );
  script_osvdb_id(
    2819,
    10454,
    10781,
    10782,
    10783,
    10784,
    10785,
    10786,
    19196,
    59519
  );

  script_name(english:"MediaWiki < 1.3.11 Multiple Remote Vulnerabilities");
  script_summary(english:"Checks the version of MedaWiki.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that are prone to
multiple flaws, including arbitrary code execution.");
 script_set_attribute(attribute:"description", value:
"The remote host appears is running a version of MediaWiki prior to
1.3.11. It is, therefore, affected by various vulnerabilities,
including some that allow an attacker to execute arbitrary PHP code on
the remote host.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number."
  );
  script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=307067");
  script_set_attribute(attribute:"solution", value:"Upgrade to MediaWiki 1.3.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mediawiki:mediawiki");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("mediawiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport", "installed_sw/MediaWiki", "www/PHP");

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

if (version =~ "^1\.([0-2]\.|3\.([0-9]($|[^0-9])|10($|[^0-9])))")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.3.11' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
