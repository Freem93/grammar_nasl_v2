#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94051);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/06 20:34:49 $");

  script_cve_id(
    "CVE-2016-7570",
    "CVE-2016-7571",
    "CVE-2016-7572"
  );
  script_bugtraq_id(93101);
  script_osvdb_id(
    144704,
    144705,
    144706
  );

  script_name(english:"Drupal 8.x < 8.1.10 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities..");
  script_set_attribute(attribute:"description", value:
"The version of Drupal running on the remote web server is 8.x prior
to 8.1.10. It is, therefore, affected by multiple vulnerabilities :

  - A flaw exists due to improper checking for
    'Administrator comments' permissions, which allows users
    who have rights to edit a node to set the visibility for
    comments on that node. An authenticated, remote attacker
    can exploit this to adjust a node's comment visibility
    preferences without the appropriate privileges.
    (CVE-2016-7570)

  - A reflected cross-site scripting (XSS) vulnerability
    exists due to a failure to validate input when handling
    HTTP exception messages before returning it to users. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2016-7571)

  - A flaw exists in the system.temporary route due to a
    failure to check 'Export configuration' permissions. An
    authenticated, remote attacker can exploit this to
    bypass intended access restrictions and download the
    full config export, resulting in the disclosure of
    sensitive information. (CVE-2016-7572)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2016-004");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.1.10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 8.1.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

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


if (version == "8")
  audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

if (version =~ "^8(\.0|\.1)?($|[^0-9])")
{
  if (ver_compare(ver:version,fix:"8.1.10",strict:FALSE) < 0)
    fix = "8.1.10";
  else
    audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
}

if (!fix)
  audit(AUDIT_WEB_APP_NOT_INST, app + " 8.x", port);

items = make_array("Installed version", version,
                   "Fixed version", fix,
                   "URL", url
                  );

order = make_list("URL", "Installed version", "Fixed version");
report = report_items_str(report_items:items, ordered_fields:order);

security_report_v4(
    port:port,
    severity:SECURITY_WARNING,
    extra: report,
    xss: TRUE
);
