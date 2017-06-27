#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18430);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/06/12 22:35:12 $");

  script_cve_id("CVE-2005-1888");
  script_bugtraq_id(13861);
  script_osvdb_id(17107);

  script_name(english:"MediaWiki < 1.3.13 / 1.4.5 / 1.5.0 alpha2 Page Template Inclusions HTML Attributes XSS");
  script_summary(english:"Checks version of MediaWiki."); 

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
cross- site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
MediaWiki running on the remote host is affected by a cross-site
scripting vulnerability due to a failure to sanitize user-supplied
input passed to certain HTML attributes when including a template
inside a style directive when editing an entry. An attacker can
exploit this flaw to inject arbitrary HTML and script code to be
executed by a user's browser within the context of an affected site.");
  script_set_attribute(attribute:"see_also", value:"http://bugzilla.wikimedia.org/show_bug.cgi?id=2304");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki 1.3.13 or later if using 1.3 legacy series;
otherwise, upgrade to 1.4.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mediawiki:mediawiki");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

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

if (version =~ "^1\.([0-2]\.|3\.([0-9]($|[^0-9])|1[0-2])|4\.[0-4]($|[^0-9.])|5 alpha1)")
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : 1.3.13 / 1.4.5 / 1.5.0 alpha2' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
