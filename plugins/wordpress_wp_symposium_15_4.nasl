#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83524);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_cve_id("CVE-2015-3325");
  script_bugtraq_id(74237);
  script_osvdb_id(120821);

  script_name(english:"WP Symposium Plugin for WordPress forum.php 'show' Parameter SQL Injection (Version Check)");
  script_summary(english:"Checks version of WP Symposium plugin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WordPress WP Symposium Plugin installed on the remote host is
affected by a SQL injection vulnerability due to a failure to properly
sanitize user-supplied input to the 'show' parameter of the forum.php
script. An unauthenticated, remote attacker can exploit this issue to
launch a SQL injection attack against the affected application,
resulting in the manipulation and disclosure of arbitrary data.

Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://openwall.com/lists/oss-security/2015/04/14/5");
  # http://packetstormsecurity.com/files/131801/WordPress-WP-Symposium-15.1-SQL-Injection.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e78198c");
  script_set_attribute(attribute:"see_also", value:"https://plugins.trac.wordpress.org/changeset/1153677/wp-symposium");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WP Symposium Plugin version 15.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Wordpress WP Symposium 15.1 SQL Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wpsymposium:wp_symposium");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl", "wordpress_wp_symposium_gid_sql_injection.nasl");
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

plugin = 'WP Symposium';
# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);
if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

res = http_send_recv3(
  method       : "GET",
  port         : port,
  item         : dir + "/wp-content/plugins/wp-symposium/readme.txt",
  exit_on_fail : TRUE
);

if (
  'Author: WP Symposium' >< res[2] &&
  'Stable tag:' >< res[2] &&
  'Tested up to:' >< res[2]
)
{
  version = UNKNOWN_VER;
  # Grab version
  match = eregmatch(pattern:"Stable tag: ([0-9\.]+)", string:res[2]);
  if (!empty_or_null(match)) version = match[1];
}
else exit(0, "Failed to read the 'readme.txt' file for the "+app+ " " + plugin + " plugin located at " + install_url);

if (version == UNKNOWN_VER)
  exit(0, "Unable to determine the version of the " +plugin+ " plugin located on the " +app+ " install at " +install_url);

fix = '15.4';
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : ' +fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + ' plugin', version);
