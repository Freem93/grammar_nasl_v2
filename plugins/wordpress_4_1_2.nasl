#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83053);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_cve_id("CVE-2015-3438", "CVE-2015-3439");
  script_bugtraq_id(74269, 75146);
  script_osvdb_id(121085, 121086, 121087);

  script_name(english:"WordPress < 3.7.6 / 3.8.6 / 3.9.4 / 4.1.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the WordPress application running
on the remote web server is potentially affected by multiple
vulnerabilities :

  - An unspecified flaw exists that allows an attacker to
    upload arbitrary files with invalid or unsafe names.
    Note that this only affects versions 4.1 and higher.
    (VulnDB 121085)

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input. A remote
    attacker, using a specially crafted request, can exploit
    this to execute arbitrary script code in a user's
    browser session. (VulnDB 121086)

  - A limited cross-site scripting vulnerability exists due
    to improper validation of user-supplied input. A remote
    attacker, using a specially crafted request, can exploit
    this to execute arbitrary script code in a user's
    browser session. Note that this only affects versions
    3.9 and higher. (VulnDB 121087)

  - An unspecified SQL injection vulnerability exists in
    some plugins.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/news/2015/04/wordpress-4-1-2/");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_4.1.2");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_3.9.4");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_3.8.6");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_3.7.6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress 3.7.6 / 3.8.6 / 3.9.4 / 4.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions less than 4.1.2 are vulnerable
# https://wordpress.org/download/release-archive/
if (
  # Short version
  version == "3.7" ||
  version == "3.8" ||
  version == "3.9" ||
  version == "4.1" ||
  # Longer versions
  (ver[0] < 3) ||
  (ver[0] == 3 && ver[1] < 7) ||
  (ver[0] == 3 && ver[1] == 7 && ver[2] < 6) ||
  (ver[0] == 3 && ver[1] == 8 && ver[2] < 6) ||
  (ver[0] == 3 && ver[1] == 9 && ver[2] < 4) ||
  (ver[0] == 4 && ver[1] < 1) ||
  (ver[0] == 4 && ver[1] == 1 && ver[2] < 2) ||
  # Short alpha / beta / RC versions
  version =~ "^(3\.[789]|4\.1)-(alpha|beta|RC)(\d+|$|[^0-9])" ||
  # Longer alpha / beta / RC versions
  version =~ "^(3\.7\.6|3\.8\.6|3\.9\.4|4\.1\.2)-(alpha|beta|RC)(\d+|$|[^0-9])"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.7.6 / 3.8.6 / 3.9.4 / 4.1.2' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
