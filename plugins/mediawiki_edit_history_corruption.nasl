#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19949);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/06/12 22:35:12 $");

  script_cve_id("CVE-2005-3166", "CVE-2005-3167");
  script_bugtraq_id(15024, 15041);
  script_osvdb_id(19877, 19956);

  script_name(english:"MediaWiki < 1.3.17 / 1.4.11 / 1.5.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MediaWiki.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the version of MediaWiki running on
the remote host is affected by multiple vulnerabilities :

  - A denial of service vulnerability exists due to an
    unspecified flaw in 'edit submission handling' that
    causes the corruption of the previous submission. A
    remote attacker can exploit this via a crafted URL. A
    spam bot known to be active in the wild can reportedly
    trigger this issue. (CVE-2005-3166)

  - A cross-site scripting vulnerability exists due to
    improper sanitization of user-supplied input for HTML
    inline style attributes. (CVE-2005-3167)");
  script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/forum/forum.php?forum_id=501174");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki 1.3.17 / 1.4.11 / 1.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mediawiki:mediawiki");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

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

if (version =~ "^1\.([0-2]\.|3\.([0-9]($|[^0-9])|1[0-6]($|[^0-9]))|4\.([0-9]($|[^0-9])|10($|[^0-9]))|5 (alpha|beta))")
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : 1.3.17 / 1.4.11 / 1.5.0' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
