#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59048);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_cve_id(
    "CVE-2012-2399",
    "CVE-2012-2400",
    "CVE-2012-2401",
    "CVE-2012-2402",
    "CVE-2012-2403"
  );
  script_bugtraq_id(53192, 58417);
  script_osvdb_id(81459, 81460, 81461, 81462, 81463, 81464);

  script_name(english:"WordPress < 3.3.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the WordPress install hosted on the
remote web server is affected by multiple vulnerabilities :

  - The application is affected by an unspecified
    vulnerability in wp-includes/js/swfupload/swfupload.swf.
    (CVE-2012-2399)

  - The application is affected by an unspecified
    vulnerability in wp-includes/js/swfobject.js.
    (CVE-2012-2400)

  - The application contains a version of Plupload prior
    to 1.5.4 that enables scripting regardless of the
    domain from which the SWF content was loaded, which
    allows remote attackers to bypass Same Origin Policy
    via crafted content. (CVE-2012-2401)

  - The application is affected by a security bypass
    vulnerability. Successfully exploiting this issue
    would allow a site administrator to deactivate network
    wide plugins. This issue requires the application
    to run under a WordPress network. (CVE-2012-2402)

  - The application is prone to multiple cross-site
    scripting vulnerabilities. An attacker can use
    specially crafted comments and the application is
    affected when making URLs clickable.
    (CVE-2012-2403, CVE-2012-2404)

Note that Nessus has not tested for the issues, but instead has relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/news/2012/04/wordpress-3-3-2/");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.3.2");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress 3.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

# Versions less than 3.3.2 are vulnerable
if (
  ver[0] < 3 ||
  (ver[0] == 3 && ver[1] < 3) ||
  (ver[0] == 3 && ver[1] == 3 && ver[2] < 2)
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.3.2\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
