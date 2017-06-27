#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85082);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/08/09 04:39:17 $");

  script_cve_id("CVE-2015-5622", "CVE-2015-5623");
  script_osvdb_id(125143, 125144);

  script_name(english:"WordPress < 3.7.9 / 3.8.9 / 3.9.7 / 4.1.6 / 4.2.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the WordPress application running on
the remote web server is either version 3.7.x prior to 3.7.9, 3.8.x
prior to 3.8.9, 3.9.x prior to 3.9.7, 4.1.x prior to 4.1.6, or 4.2.x
prior to 4.2.3. It is, therefore, potentially affected by the
following vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists due to
    a flaw in the Shortcode API in which shortcodes embedded
    in HTML tags are not properly handled before returning
    the input to the users. A remote, authenticated attacker
    can exploit this by using a crafted request to execute
    arbitrary code in the user's browser session.
    (CVE-2015-5622)

  - An unspecified vulnerability exists due to a flaw in
    Quick Draft, which can allow an unauthorized, remote
    user to create arbitrary drafts. (CVE-2015-5623)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.7.9");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.8.9");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.9.7");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_4.1.6");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_4.2.3");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/news/2015/07/wordpress-4-2-3/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress 3.7.9 / 3.8.9 / 3.9.7 / 4.1.6 / 4.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

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

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = NULL;

if (
  (ver[0] == 4 && ver[1] == 2 && ver[2] < 3) ||
  version =~ "^4\.2\.3-(alpha|beta|RC)(\d+|$|[^0-9])"
) fix = "4.2.3";

else if (
  (ver[0] == 4 && ver[1] == 1 && ver[2] < 6) ||
   version =~ "^4\.1\.6-(alpha|beta|RC)(\d+|$|[^0-9])"
) fix = "4.1.6";

else if (
  (ver[0] == 3 && ver[1] == 9 && ver[2] < 7) ||
  version =~ "^3\.9\.7-(alpha|beta|RC)(\d+|$|[^0-9])"
) fix = "3.9.7";

else if (
  (ver[0] == 3 && ver[1] == 8 && ver[2] < 9) ||
  version =~ "^3\.8\.9-(alpha|beta|RC)(\d+|$|[^0-9])"
) fix = "3.8.9";

else if (
  (ver[0] == 3 && ver[1] == 7 && ver[2] < 9) ||
  version =~ "^3\.7\.9-(alpha|beta|RC)(\d+|$|[^0-9])"
) fix = "3.7.9";

if(fix)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : ' +fix+
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
