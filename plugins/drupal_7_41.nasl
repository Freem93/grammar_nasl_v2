#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86673);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:33:25 $");

  script_cve_id("CVE-2015-7943");
  script_bugtraq_id(77293);
  script_osvdb_id(123461);

  script_name(english:"Drupal 7.x < 7.41 Overlay Module Open Redirect");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
an open redirect vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a version of Drupal that is 7.x prior
to 7.41. It is, therefore, affected by an open redirect vulnerability
in the Overlay module due to improper validation of URLs before
displaying their contents. An unauthenticated, remote attacker can
exploit this, via a specially crafted URL, to redirect a victim from
an intended legitimate website to an arbitrary website.

This vulnerability can only be exploited against Drupal users who have
both the 'Access the administrative overlay' permission and the
Overlay module enabled. 

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2015-004");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/drupal-7.41-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.41 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

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
url = build_url(qs:dir, port:port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ "^7\.([0-9]|[1-3][0-9]|40)($|[^0-9]+)")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.41' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
