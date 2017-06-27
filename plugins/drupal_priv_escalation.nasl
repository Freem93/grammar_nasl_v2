#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18641);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/04/03 13:28:13 $");

  script_cve_id("CVE-2005-1871");
  script_bugtraq_id(13852);
  script_osvdb_id(17028);

  script_name(english:"Drupal Unspecified Privilege Escalation");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Drupal running on the remote
host is affected by a privilege escalation vulnerability due to an 
improperly implemented input check. An attacker can exploit this, when
public registration is enabled, to gain elevated privileges." );
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/files/sa-2005-001/advisory.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 4.4.3 / 4.5.3 / 4.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "installed_sw/Drupal", "Settings/ParanoidReport");
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

dir = install['path'];
version = install['version'];

loc = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Report on vulnerable (4.4.0-4.4.2; 4.5.0-4.5.2; 4.6.0)
if (version =~ "^4\.(4\.[0-2]|5\.[0-2]|6\.0)")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + loc +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.4.3 / 4.5.3 / 4.6.1' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, loc, version);
