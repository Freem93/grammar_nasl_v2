#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51939);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_cve_id("CVE-2011-0700", "CVE-2011-0701");
  script_bugtraq_id(46249);
  script_osvdb_id(72763, 72764, 72765);
  script_xref(name:"Secunia", value:"43238");

  script_name(english:"WordPress < 3.0.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application with multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the installation of WordPress hosted
on the remote web server is affected by multiple vulnerabilities :

    - The application is prone to multiple cross-site
    scripting vulnerabilities. An attacker can exploit
    these issues through the 'title' field of the
    'Quick/Bulk Edit' section and the 'tags meta box'
    section. An attacker would require Author or
    Contributor privileges to take advantage of this.

    - The application is prone to an information
    disclosure vulnerability. An attacker can exploit this
    issue through the media uploader to disclose posts.
    This information may assist in further attacks. An
    attacker would require Author privileges to take
    advantage of this.

Note that Nessus has not tested for the issues but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/news/2011/02/wordpress-3-0-5/");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.0.5");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress 3.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

# Versions < 3.0.5 are affected.
if (
  ver[0] < 3 ||
  (ver[0] == 3 && ver[1] == 0 && ver[2] < 5)
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.0.5\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
