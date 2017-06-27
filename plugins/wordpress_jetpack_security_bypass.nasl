#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73686);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/10/01 01:43:19 $");

  script_cve_id("CVE-2014-0173");
  script_bugtraq_id(66789);
  script_osvdb_id(105714);

  script_name(english:"Jetpack Plugin for WordPress Security Bypass");
  script_summary(english:"Checks version of Jetpack plugin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a
security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WordPress Jetpack plugin installed on the remote host is affected
by a security bypass vulnerability due to a flaw in the
'class.jetpack.php' script. This can allow a remote, unauthenticated
attacker to submit crafted XML-RPC requests that bypass access
controls, allowing the attacker to publish posts on a site.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://jetpack.me/2014/04/10/jetpack-security-update/");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/plugins/jetpack/changelog/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.9.4 / 2.0.6 / 2.1.4 / 2.2.7 / 2.3.7 /2.4.4 /
2.5.2 / 2.6.3 / 2.7.2 / 2.8.2 / 2.9.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:automattic:jetpack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin = "Jetpack";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "jetpack/_inc/jetpack.js"][0] =
    make_list('jetpack-module', 'jetpack\\.');

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}
if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

res = http_send_recv3(
  method       : "GET",
  item         : dir + "/wp-content/plugins/jetpack/readme.txt",
  port         : port,
  exit_on_fail : TRUE
);

if (
  '=== Jetpack by WordPress.com ===' >< res[2] &&
  'Stable tag:' >< res[2] &&
  'Tested up to:' >< res[2]
)
{
  ver = UNKNOWN_VER;
  # Grab version
  match = eregmatch(pattern:"Stable tag: ([0-9\.]+)", string:res[2]);
  if (!isnull(match)) ver = match[1];
}
else exit(0, "Failed to read the 'readme.txt' file for the WordPress " + plugin + " located at " + install_url + ".");

# beta and b[0-9] releases did not always update the stable tag
# additional check and default to this next check if they don't match
# ex: release 2.7b1 lists 2.6.1 for the Stable Tag, but shows 2.7 in the
# Changelog notes further down in the file.
readme = strstr(res[2], "== Changelog ==");
if (!isnull(readme))
{
  match = eregmatch(pattern:"= ([0-9]+\.[0-9\.]+) =", string:readme);
  if (!isnull(match)) ver2 = match[1];

  if (ver != ver2) ver = ver2;
}

fix = FALSE;

if (ver =~ '^1\\.9' && ver_compare(ver:ver, fix:'1.9.4', strict:FALSE) < 0)
  fix = '1.9.4';

else if (ver =~ '^2\\.0' && ver_compare(ver:ver, fix:'2.0.6', strict:FALSE) < 0)
  fix = '2.0.6';

else if (ver =~ '^2\\.1' && ver_compare(ver:ver, fix:'2.1.4', strict:FALSE) < 0)
  fix = '2.1.4';

else if (ver =~ '^2\\.2' && ver_compare(ver:ver, fix:'2.2.7', strict:FALSE) < 0)
  fix = '2.2.7';

else if (ver =~ '^2\\.3' && ver_compare(ver:ver, fix:'2.3.7', strict:FALSE) < 0)
  fix = '2.3.7';

else if (ver =~ '^2\\.4' && ver_compare(ver:ver, fix:'2.4.4', strict:FALSE) < 0)
  fix = '2.4.4';

else if (ver =~ '^2\\.5' && ver_compare(ver:ver, fix:'2.5.2', strict:FALSE) < 0)
  fix = '2.5.2';

else if (ver =~ '^2\\.6' && ver_compare(ver:ver, fix:'2.6.3', strict:FALSE) < 0)
  fix = '2.6.3';

else if (ver =~ '^2\\.7' && ver_compare(ver:ver, fix:'2.7.2', strict:FALSE) < 0)
  fix = '2.7.2';

else if (ver =~ '^2\\.8' && ver_compare(ver:ver, fix:'2.8.2', strict:FALSE) < 0)
  fix = '2.8.2';

else if (ver =~ '^2\\.9' && ver_compare(ver:ver, fix:'2.9.3', strict:FALSE) < 0)
  fix = '2.9.3';

if (fix)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +ver+
      '\n  Fixed version     : ' +fix + '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + ' plugin', ver);
