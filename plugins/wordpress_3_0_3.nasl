#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51341);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_cve_id("CVE-2010-5106");
  script_bugtraq_id(45299);
  script_osvdb_id(69761);
  script_xref(name:"Secunia", value:"42553");

  script_name(english:"WordPress < 3.0.3 XML-RPC Interface Access Restriction Bypass");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application with a security
bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the installation of WordPress is
prior to 3.0.3. It is, therefore, affected by a security bypass
vulnerability. Certain access control restrictions are not properly
enforced, which could allow a remote, authenticated user to perform
unauthorized actions such as editing, publishing, or deleting existing
posts using specially crafted XML-RPC requests.

Note that a user must have 'Author Level' or 'Contributor Level'
permissions to exploit this issue. Additionally, remote publishing
(which is disabled by default) must be enabled.");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/news/2010/12/wordpress-3-0-3/");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.0.3");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress 3.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP", "Settings/ParanoidReport");
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

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions < 3.0.3 are affected.
if (
  ver[0] < 3 ||
  (ver[0] == 3 && ver[1] == 0 && ver[2] < 3)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.0.3\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
