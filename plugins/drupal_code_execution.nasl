#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(18639);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2005-2106");
  script_bugtraq_id(14110);
  script_osvdb_id(17647);

  script_name(english:"Drupal Public Comment/Posting Arbitrary PHP Code Execution");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Drupal
running on the remote host is affected by a remote code execution
vulnerability. An unspecified flaw allows attackers to embed arbitrary
PHP code when submitting a comment or posting, allowing the execution
of arbitrary code. Note that successful exploitation requires that
public comments or postings be allowed in Drupal." );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jun/293");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/drupal-4.6.2");
  script_set_attribute(attribute:"solution", value:"Upgrade to Drupal version 4.5.4 / 4.6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Drupal", "www/PHP", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

ver = install['version'];
url = build_url(qs:install['path'], port:port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Report on vulnerable (4.5.0 - 4.5.3; 4.6.0 - 4.6.1)
if (ver =~ "^4\.(5\.[0-3]|6\.[01])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 4.5.4 / 4.6.2' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);
