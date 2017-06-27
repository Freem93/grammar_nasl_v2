#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92626);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/08/16 13:21:45 $");

  script_osvdb_id(141497);
  script_xref(name:"EDB-ID", value:"40149");

  script_name(english:"Drupal Coder Module Deserialization RCE");
  script_summary(english:"Attempts to send a request to check if vulnerable script is accessible.");

  script_set_attribute( attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a
remote code execution vulnerability.");
  script_set_attribute( attribute:"description", value:
"The version of Drupal running on the remote web server is affected by
a remote code execution vulnerability in the Coder module,
specifically in file coder_upgrade.run.php, due to improper validation
of user-supplied input to the unserialize() function. An
unauthenticated, remote attacker can exploit this, via a specially
crafted request, to execute arbitrary PHP code.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/node/2765575");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/coder");
  script_set_attribute(attribute:"solution", value:
"Upgrade the Coder module to version 7.x-1.3 / 7.x-2.6 or later.
Alternatively, remove the entire Coder module directory from any
publicly accessible website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_require_ports("Services/www",80);
  script_require_keys("installed_sw/Drupal", "www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);

plugin = "Coder";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

# Check in /sites/all/modules/
if (!installed)
{
  checks = make_array();
  # Default module path for custom/contributed modules
  module_path = "/sites/all/modules";
  checks[module_path + "/coder/README.txt"][0] = make_list('[Cc]oder');

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}

# Check in /modules/ for edge case installs
if (!installed)
{
  checks = make_array();
  # typically reserved for core modules, but admins may install modules here
  module_path = "/modules";
  checks[module_path + "/coder/README.txt"][0] = make_list('[Cc]oder');

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}

if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " module");

# Check if coder_upgrade.run.php exists and returns match_txt
# since fix for this issue prevents coder_upgrade.run.php from
# being executed as a CGI and match txt won't be returned if it's
# patched.
module_url = "/coder/coder_upgrade/scripts/coder_upgrade.run.php";

# set module_path for conditions where "installed" is fetched from
# KB instead of check_webapp_ext checks
if (!module_path) module_path = "/sites/all/modules";

res = http_send_recv3(method:"GET", item:dir+module_path+module_url, port:port, exit_on_fail:TRUE);
match_txt = "file parameter is not setNo path to parameter file";

if(match_txt >< res[2])
{
  output = strstr(res[2], match_txt);
  if (empty_or_null(output)) output = res[2];

  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    generic     : TRUE,
    request     : make_list(install_url + module_path + module_url),
    output      : chomp(output)
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
