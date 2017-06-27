#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64452);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_cve_id("CVE-2013-0235", "CVE-2013-0236", "CVE-2013-0237");
  script_bugtraq_id(57554, 57555);
  script_osvdb_id(89138, 89576, 89577);

  script_name(english:"WordPress < 3.5.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the WordPress install hosted on the
remote web server is affected by multiple vulnerabilities :

  - The application is affected by a server-side request
    forgery vulnerability in the 'pingback.ping' method
    used in 'xmlrpc.php'. This vulnerability can be used to
    expose information and remotely port scan a host using
    pingbacks. (CVE-2013-0235)

  - The application is affected by two instances of
    cross-site scripting (XSS) attacks via shortcodes and
    post content. (CVE-2013-0236)

  - The application is affected by a cross-site scripting
    (XSS) vulnerability in the Plupload external library.
    (CVE-2013-0237)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/FireFart/WordpressPingbackPortScanner");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525045/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://lab.onsec.ru/2013/01/wordpress-xmlrpc-pingback-additional.html");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/news/2013/01/wordpress-3-5-1/");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.5.1");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress 3.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

# Versions less than 3.5.1 are vulnerable
if (
  ver[0] < 3 ||
  (ver[0] == 3 && ver[1] < 5) ||
  (ver[0] == 3 && ver[1] == 5 && ver[2] < 1)
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.5.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
