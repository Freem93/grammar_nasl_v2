#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83138);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/30 14:08:21 $");

  script_bugtraq_id(74334);
  script_osvdb_id(121320);

  script_name(english:"WordPress <= 3.9.5 / 4.1.x < 4.1.4 / 4.2.x < 4.2.1 Comments Stored XSS");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The PHP application running on the remote web server is affected by
a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the WordPress application running on
the remote web server is affected by an input validation flaw that
allows an unauthenticated attacker to inject JavaScript into WordPress
comments, which could result in a stored cross-site scripting attack
being carried out when the affected comment is later viewed.
 
Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_4.2.1");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_4.1.4");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2015/Apr/84");
  script_set_attribute(attribute:"see_also", value:"http://klikki.fi/adv/wordpress2.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress 4.1.4 / 4.2.1 or later.

As a workaround, disable comments and do not approve any comments.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/29");

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

# Vulnerable:
# <= 3.9.5
# 4.1.x < 4.1.4
# 4.2.x < 4.2.1
# https://wordpress.org/download/release-archive/
if (
  # Short version
  version == "3.9"   ||
  version == "4.1"   ||
  version == "4.2"   ||
  # Longer versions
  (ver[0] < 3) ||
  (ver[0] == 3 && ver[1] < 9) ||
  (ver[0] == 3 && ver[1] == 9 && ver[2] <= 5) ||
  (ver[0] == 4 && ver[1] < 1) ||
  (ver[0] == 4 && ver[1] == 1 && ver[2] < 4) ||
  (ver[0] == 4 && ver[1] == 2 && ver[2] < 1) ||
  # Longer alpha / beta / RC version
  version =~ "^4\.1\.4-(alpha|beta|RC)(\d+|$|[^0-9])" ||
  version =~ "^4\.2\.1-(alpha|beta|RC)(\d+|$|[^0-9])"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 4.1.4 / 4.2.1' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
