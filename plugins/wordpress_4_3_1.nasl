#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85985);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/01/17 15:50:10 $");

  script_cve_id("CVE-2015-5714", "CVE-2015-5715");
  script_bugtraq_id(76744, 76745, 76748);
  script_osvdb_id(127562, 127563);

  script_name(english:"WordPress < 4.3.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the WordPress application running on
the remote web server is prior to 4.3.1. It is, therefore, potentially
affected by multiple vulnerabilities :

  - A cross-site scripting vulnerability exists when
    processing shortcode tags due to improper validation of
    user-supplied input. An attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2015-5714)

  - An unspecified vulnerability exists that allows an
    authenticated attacker to publish private posts and make
    them 'sticky'. (CVE-2015-5715)

  - An unspecified cross-site scripting vulnerability exists
    in the user list table. An attacker can exploit this,
    via a specially crafted request, to execute arbitrary
    script code in a user's browser session.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_4.3.1");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/news/2015/09/wordpress-4-3-1/");
  # http://blog.checkpoint.com/2015/09/15/finding-vulnerabilities-in-core-wordpress-a-bug-hunters-trilogy-part-iii-ultimatum/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?edee75c9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress 4.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/17");

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

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# All versions of WordPress prior to 4.3.1 are vulnerable
# and according to the release archive 4.2.5, 4.3.1 and
# in the 4.x range, to date. WordPress claims that the
# archive in the link below is a comprehensive list of
# every release that they know of, on record.
# https://wordpress.org/download/release-archive/
# Contains all of the release dates:
# https://codex.wordpress.org/WordPress_Versions

if(
  (ver[0] < 3) ||
  # Patches were backported into unsupported versions
  # 3.7.x - 3.9.x
  (ver[0] == 3 && ver[1] < 7) ||
  (ver[0] == 3 && ver[1] == 7 && ver[2] < 11) ||
  (ver[0] == 3 && ver[1] == 8 && ver[2] < 11) ||
  (ver[0] == 3 && ver[1] == 9 && ver[2] < 9) ||
  # 4.0.x - 4.3.x
  (ver[0] == 4 && ver[1] == 0 && ver[2] < 8) ||
  (ver[0] == 4 && ver[1] == 1 && ver[2] < 8) ||
  (ver[0] == 4 && ver[1] == 2 && ver[2] < 5) ||
  (ver[0] == 4 && ver[1] == 3 && ver[2] < 1)
  )
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.3.1' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
