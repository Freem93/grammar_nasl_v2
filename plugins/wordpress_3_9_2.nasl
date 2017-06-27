#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77157);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_cve_id(
    "CVE-2014-2053",
    "CVE-2014-5203",
    "CVE-2014-5204",
    "CVE-2014-5205",
    "CVE-2014-5240",
    "CVE-2014-5265",
    "CVE-2014-5266"
  );
  script_bugtraq_id(69096);
  script_osvdb_id(104475, 109867, 109868, 109869, 109870);

  script_name(english:"WordPress < 3.7.4 / 3.8.4 / 3.9.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the WordPress application hosted on
the remote web server is affected by multiple vulnerabilities :

  - An XML injection flaw exists within 'getid3.lib.php'
    due to the parser accepting XML external entities
    from untrusted sources. Using specially crafted XML
    data, a remote attacker could access sensitive
    information or cause a denial of service. This affects
    versions 3.6 - 3.9.1, except 3.7.4 and 3.8.4.

  - An XML injection flaw exists within 'xmlrpc.php' due to
    the parser accepting XML internal entities without
    properly validating them. Using specially crafted XML
    data, a remote attacker could cause a denial of service.
    This affects versions 1.5 - 3.9.1, except 3.7.4 and
    3.8.4.

  - An unsafe serialization flaw exists in the script
    '/src/wp-includes/class-wp-customize-widgets.php' when
    processing widgets. This could allow a remote attacker
    to execute arbitrary code. Versions 3.9 and 3.9.1
    non-default configurations are affected.

  - A flaw exists when building CSRF tokens due to it not
    separating pieces by delimiter and not comparing nonces
    in a time-constant manner. This could allow a remote
    attacker to conduct a brute force attack and potentially
    disclose the CSRF token. This affects versions 2.0.3 -
    3.9.1, except 3.7.4 and 3.8.4.

  - A cross-site scripting flaw exists in the function
    'get_avatar' within the '/src/wp-includes/pluggable.php'
    script where input from the avatars is not validated
    before returning it to the user. Using a specially
    crafted request, an authenticated attacker could execute
    arbitrary script code within the browser / server trust
    relationship. This affects version 3.9.1.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/news/2014/08/wordpress-3-9-2/");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.9.2");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/301");
  script_set_attribute(attribute:"see_also", value:"https://core.trac.wordpress.org/changeset/29405/branches/3.9");
  script_set_attribute(attribute:"see_also", value:"https://core.trac.wordpress.org/changeset/29389");
  script_set_attribute(attribute:"see_also", value:"https://core.trac.wordpress.org/changeset/29390");
  script_set_attribute(attribute:"see_also", value:"https://core.trac.wordpress.org/changeset/29384");
  script_set_attribute(attribute:"see_also", value:"https://core.trac.wordpress.org/changeset/29408");
  script_set_attribute(attribute:"see_also", value:"https://core.trac.wordpress.org/changeset/29398");

  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress 3.7.4 / 3.8.4 / 3.9.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

# Versions 1.5 < 3.7.4 / 3.8.4 / 3.9.2 are vulnerable
if (
     (ver[0] == 1 && ver[1] >= 5) ||
     (ver[0] == 2) ||
     (ver[0] == 3 && ver[1] <= 6) ||
     (ver[0] == 3 && ver[1] == 7 && ver[2] < 4) ||
     (ver[0] == 3 && ver[1] == 8 && ver[2] < 4) ||
     (ver[0] == 3 && ver[1] == 9 && ver[2] < 2)
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.7.4 / 3.8.4 / 3.9.2\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
