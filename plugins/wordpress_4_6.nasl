#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93111);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/01 21:55:33 $");

  script_cve_id("CVE-2016-6896", "CVE-2016-6897", "CVE-2016-10148");
  script_bugtraq_id(92572, 92573);
  script_osvdb_id(143416, 143345, 150699);
  script_xref(name:"EDB-ID", value:"40288");

  script_name(english:"WordPress 4.5.x < 4.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is 4.5.x prior to 4.6. It
is, therefore, affected by multiple vulnerabilities :

  - A path traversal vulnerability exists in the WordPress
    Admin API in the wp_ajax_update_plugin() function in
    ajax-actions.php due to improper sanitization of
    user-supplied input. An authenticated, remote attacker
    can exploit this, via a specially crafted request, to
    cause a denial of service condition. (CVE-2016-6896)

  - A cross-site request forgery vulnerability (XSRF) exists
    in the admin-ajax.php script due to a failure to require
    multiple steps, explicit confirmation, or a unique token
    when performing certain sensitive actions. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to follow a specially crafted link, to
    perform arbitrary AJAX updates. (CVE-2016-6897)

  - An information disclosure vulnerability exists in the
    wp_ajax_update_plugin() function in the ajax-actions.php
    script due to performing a call to get_plug_data()
    before checking capabilities. An authenticated, remote
    attacker can exploit this to bypass intended read-access
    restrictions, resulting in a disclosure of sensitive
    information. (CVE-2016-10148)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/news/2016/08/pepper/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2016/Aug/98");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "WordPress";
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
install_url = build_url(port:port, qs:dir);

if (version =~ "^4$")
  audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

# Per https://wordpress.org/download/release-archive/
# only 4.6.x is currently supported :
# "None of these are safe to use, except the latest in the 4.6 series, which is actively maintained."
# Also since 4.6.0 is the first of the 4.6 branch, we only concern ourselves with 4.5.x :
if (version !~ "^4\.5($|[^0-9])")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);

report =
  '\n  URL               : ' + install_url +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : 4.6' +
  '\n';
security_report_v4(severity:SECURITY_WARNING, port:port, extra:report, xsrf:TRUE);
