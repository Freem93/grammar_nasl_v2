#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51860);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/09 15:53:04 $");

  script_cve_id(
    "CVE-2010-4257",
    "CVE-2010-5294",
    "CVE-2010-5295",
    "CVE-2010-5296"
  );
  script_bugtraq_id(
    45131,
    65233,
    65240,
    73661
  );
  script_osvdb_id(
    68411,
    69536,
    104574,
    104689
  );
  script_xref(name:"Secunia", value:"42431");

  script_name(english:"WordPress < 3.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the installation of WordPress hosted
on the remote web server is affected by multiple vulnerabilities :

  - A SQL injection vulnerability exists in the
    'wp-includes/comment.php' script due to improper
    sanitization of user-supplied input to the 'Send
    Trackbacks' field. A remote attacker can exploit this to
    inject or manipulate SQL queries to manipulate or
    disclose arbitrary data. (CVE-2010-4257)

  - A cross-site scripting vulnerability exists in the
    request_filesystem_credentials() function in the
    'wp-admin/includes/file.php' script where input passed
    from an error message for an FTP or SSH connection
    attempt is not validated. This allows a
    context-dependent attacker to use a specially crafted
    request to execute arbitrary script code within the
    user's browser session. (CVE-2010-5294)

  - A cross-site scripting vulnerability exists in the
    'wp-admin/plugins.php' script due to improper validation
    of input supplied via a plugin's 'author' field. This
    allows a remote attacker to inject arbitrary script or
    HTML code in a user's browser session. (CVE-2010-5295)

  - A security bypass vulnerability exists in the
    'wp-includes/capabilities.php' script. When a multisite
    configuration is used, Super Admin privileges are not
    needed for the 'delete_users' capability. This allows an
    authenticated attacker to bypass access restrictions.
    (CVE-2010-5296)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/news/2010/11/wordpress-3-0-2");
  script_set_attribute(attribute:"see_also", value:"https://core.trac.wordpress.org/changeset/16373");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.0.2");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress 3.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/03");

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

# Versions < 3.0.2 are affected.
if (
  ver[0] < 3 ||
  (ver[0] == 3 && ver[1] == 0 && ver[2] < 2)
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSS', value: TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.0.2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
