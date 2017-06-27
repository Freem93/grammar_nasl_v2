#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62046);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/10/01 01:43:19 $");

  script_cve_id("CVE-2012-4421", "CVE-2012-4422");
  script_bugtraq_id(55455);
  script_osvdb_id(85192, 85193);

  script_name(english:"WordPress < 3.4.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the WordPress install hosted on the
remote web server is affected by multiple vulnerabilities :

  - The application is affected by an unspecified
    bug that affects multisite installs with untrusted
    users.

  - The application is affected by an unspecified
    vulnerability that may allow for privilege escalation
    in the Atom Publishing Protocol endpoint.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/news/2012/09/wordpress-3-4-2/");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.4.2");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress 3.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

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

# Versions less than 3.4.2 are vulnerable
if (
  ver[0] < 3 ||
  (ver[0] == 3 && ver[1] < 4) ||
  (ver[0] == 3 && ver[1] == 4 && ver[2] < 2)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.4.2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
