#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83351);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/19 18:10:51 $");

  script_cve_id("CVE-2015-3440");
  script_bugtraq_id(74334);
  script_osvdb_id(121320);
  script_xref(name:"EDB-ID", value:"36844");

  script_name(english:"WordPress Multiple XSS");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The PHP application running on the remote web server is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the WordPress application running on
the remote web server is either version 3.7.x prior to 3.7.8, 3.8.x
prior to 3.8.8, 3.9.x prior to 3.9.6, 4.1.x prior to 4.1.5, or 4.2.x
prior to 4.2.2. It is, therefore, potentially affected by multiple
cross-site scripting vulnerabilities :

  - An HTML file in the Genericons icon font package is
    vulnerable to a cross-site scripting attack. This
    package is used in various themes and plugins.

  - A cross-site scripting vulnerability exists that was
    only partially fixed in the 4.2.1 release.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.7.8");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.8.8");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.9.6");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_4.1.5");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_4.2.2");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/news/2015/05/wordpress-4-2-2/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress 3.7.8 / 3.8.8 / 3.9.6 / 4.1.5 / 4.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

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

# Vulnerable:
# 3.7.x < 3.7.8
# 3.8.x < 3.8.8
# 3.9.x < 3.9.6
# 4.1.x < 4.1.5
# 4.2.x < 4.2.2
# https://wordpress.org/download/release-archive/
fix = NULL;


if ((ver[0] == 3 && ver[1] == 7 && ver[2] < 8) ||
   version =~ "^3\.7\.8-(alpha|beta|RC)(\d+|$|[^0-9])"
   )
    fix = "3.7.8";

else if ((ver[0] == 3 && ver[1] == 8 && ver[2] < 8) ||
   version =~ "^3\.8\.8-(alpha|beta|RC)(\d+|$|[^0-9])"
   )
    fix = "3.8.8";

else if ((ver[0] == 3 && ver[1] == 9 && ver[2] < 6) ||
   version =~ "^3\.9\.6-(alpha|beta|RC)(\d+|$|[^0-9])"
   )
    fix = "3.9.6";

else if ((ver[0] == 4 && ver[1] == 1 && ver[2] < 5) ||
   version =~ "^4\.1\.5-(alpha|beta|RC)(\d+|$|[^0-9])"
   )
    fix = "4.1.5";

else if ((ver[0] == 4 && ver[1] == 2 && ver[2] < 2) ||
   version =~ "^4\.2\.2-(alpha|beta|RC)(\d+|$|[^0-9])"
   )
    fix = "4.2.2";

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
