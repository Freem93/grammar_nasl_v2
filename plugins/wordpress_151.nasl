#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18301);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/02/13 21:07:14 $");

  script_cve_id("CVE-2005-1687", "CVE-2005-1688");
  script_bugtraq_id(13655, 13663, 13664);
  script_osvdb_id(16701, 16702, 16703);

  script_name(english:"WordPress < 1.5.1 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in WordPress < 1.5.1.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of WordPress installed on the remote host is affected by
multiple vulnerabilities :

  - The application is affected by a SQL injection
    vulnerability because it fails to properly sanitize
    user-supplied input passed via the 'tb_id' parameter
    to the 'wp-trackback.php' script before using it in
    database queries. This could lead to disclosure of
    sensitive information or attacks against the underlying
    database. (CVE-2005-1687)

  - The application contains an information disclosure flaw
    in which paths can be exposed in error messages after
    direct requests to files in '/wp-content/themes/',
    '/wp-includes', and '/wp-admin/'.  (CVE-2005-1688)

  - The application is affected by multiple cross-site
    scripting vulnerabilities. An attacker can pass
    arbitrary HTML and script code through the 's'
    parameter of the 'wp-admin/edit.php' script or the
    'p' parameter in the 'wp-admin/post.php' script, thereby
    facilitating cross-site scripting attacks. Note that
    these attacks will only be successful against
    administrators since the scripts themselves are limited
    to administrators.");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/development/2005/05/one-five-one/");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress version 1.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencie("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
ver = install['version'];
install_url = build_url(port:port, qs:dir);

# Try a SQL injection.
# nb: this should lead to a syntax error.
postdata =
  "tb_id=-99'" + SCRIPT_NAME + "&" +
  "url=http://wordpress.org/development/2005/05/one-five-one/&" +
  "title=" + SCRIPT_NAME + "&" + "blog_name=Nessus";

w = http_send_recv3(method: "POST", port:port,
  item:  dir + "/wp-trackback.php",
  data: postdata, exit_on_fail: TRUE);
res = w[2];

# There's a problem if we see a database error with the plugin's name.
if (
  "<p class='wpdberror'>" >< res &&
  "FROM wp_posts WHERE ID = -99'" + SCRIPT_NAME >< res
)
{
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  security_hole(port);
  exit(0);
}

# Alert on the version number in case magic_quotes was enabled.
# Ensure we are running as paranoid
if (report_paranoia == 2)
{
  if (ver =~ "^(0\.|1\.([0-4]|5([^0-9.]+|$|\.0)))")
  {
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    if (report_verbosity > 0)
    {
      report =
        '\n  URL               : ' + install_url +
        '\n  Installed version : ' + ver +
        '\n  Fixed version     : 1.5.1\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
