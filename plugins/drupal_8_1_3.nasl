#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91781);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/25 14:52:52 $");

  script_osvdb_id(140142, 140143);
  script_bugtraq_id(91230);

  script_name(english:"Drupal 7.x < 7.44 / 8.x < 8.1.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Drupal running on the remote web server is 7.x prior to
7.44 or 8.x prior to 8.1.3. It is, therefore, affected by the
following vulnerabilities :

  - A flaw exists in the Views module that allows an
    unauthenticated, remote attacker to bypass restrictions
    and disclose the number of hits collected by the
    Statistics module. (VulnDB 140142)

  - A flaw exists in the User module due to incorrectly
    granting the 'all user' role when saving user accounts.
    An authenticated, remote attacker can exploit this to
    gain elevated privileges. (VulnDB 140143)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2016-002");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.44");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.1.3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.44 / 8.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
url = build_url(qs:dir, port:port);
fix = FALSE ;


if (version == "7" || version == "8") audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

if (version =~ "^7\.")
{
  if (ver_compare(ver:version,fix:"7.44",strict:FALSE) < 0)
  {
    fix = "7.44";
  }else{
    audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
  }
}

if (version =~ "^8\.")
{
  if (ver_compare(ver:version,fix:"8.1.3",strict:FALSE) < 0)
  {
    fix = "8.1.3";
  }else{
    audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
  }
}

if (!fix) audit(AUDIT_WEB_APP_NOT_INST, app + " 7.x or 8.x", port);

security_report_v4(
    port:port,
    severity:SECURITY_HOLE,
    extra:
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n'
);
