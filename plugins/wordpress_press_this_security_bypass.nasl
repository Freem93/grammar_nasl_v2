#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72961);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/10/01 01:43:19 $");

  script_cve_id("CVE-2011-5270");
  script_bugtraq_id(47598);
  script_osvdb_id(72097);

  script_name(english:"WordPress 'press-this.php' Security Bypass");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the WordPress install hosted on the
remote web server is affected by a security bypass vulnerability.

A flaw in the 'wp-admin/press-this.php' script improperly checks user
permissions when publishing posts. This allows a user with
'Contributor-level' privileges to post as if they had 'publish_posts'
permissions.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://core.trac.wordpress.org/changeset/17710");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.0.6");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.1.2");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/news/2011/04/wordpress-3-1-2/");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress 3.0.6 / 3.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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

# Versions less than 3.0.6 or 3.1.2 are vulnerable
if(
  ver[0] < 3 ||
  (ver[0] == 3 && ver[1] == 0 && ver[2] < 6) ||
  (ver[0] == 3 && ver[1] == 1 && ver[2] < 2)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.0.6 / 3.1.2';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
