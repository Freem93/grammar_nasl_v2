#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72984);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/13 21:07:14 $");

  script_cve_id("CVE-2012-6633", "CVE-2012-6634", "CVE-2012-6635");
  script_bugtraq_id(65218, 65220, 65221);
  script_osvdb_id(82627, 102546, 102547);

  script_name(english:"WordPress < 3.3.3 / 3.4.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the WordPress install hosted on the
remote web server is affected by the following vulnerabilities :

  - A cross-site scripting flaw exists in the
    'edit-tags.php' script where it does not validate the
    'slug' parameter upon submission. This could allow a
    remote attacker to create a specially crafted request
    that would execute arbitrary script code in a user's
    browser session within the trust relationship between
    the browser and server. (CVE-2012-6633)

  - A flaw exists in the 'wp-admin/media-upload.php' script
    where input for the 'post_id' parameter is not properly
    sanitized. This could allow a remote attacker to access
    potentially sensitive information or bypass
    media-attachment restrictions. (CVE-2012-6634)

  - A flaw exists in the
    'wp-admin/includes/class-wp-posts-list-table.php'
    script where it fails to restrict access to the
    excerpt-view. This could allow a remote attacker to
    access potentially sensitive information when viewing a
    draft. (CVE-2012-6635)

  - Some hardening was applied to prevent unfiltered HTML in
    comments. This could potentially allow clickjacking.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.3.3");
  script_set_attribute(attribute:"see_also", value:"https://core.trac.wordpress.org/changeset/21083");
  script_set_attribute(attribute:"see_also", value:"https://core.trac.wordpress.org/changeset/21086");
  script_set_attribute(attribute:"see_also", value:"https://core.trac.wordpress.org/changeset/21087");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress 3.3.3 / 3.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

# Versions less than 3.3.3 are vulnerable
if(
  ver[0] < 3 ||
  (ver[0] == 3 && ver[1] < 3) ||
  (ver[0] == 3 && ver[1] == 3 && ver[2] < 3)
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.3.3 / 3.4.0\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
