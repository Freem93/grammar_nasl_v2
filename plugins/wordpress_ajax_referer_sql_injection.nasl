#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25291);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/11/02 20:50:26 $");

  script_cve_id("CVE-2007-2821");
  script_bugtraq_id(24076);
  script_osvdb_id(36311);
  script_xref(name:"EDB-ID", value:"3960");

  script_name(english:"WordPress check_ajax_referer() Function SQL Injection");
  script_summary(english:"Attempts to generate a SQL error.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack.");
  script_set_attribute(attribute:"description", value:
"The version of WordPress on the remote host fails to properly sanitize
input to the 'cookie' parameter of the 'wp-admin/admin-ajax.php'
script before using it in the 'check_ajax_referer' function in
database queries. Regardless of PHP's 'magic_quotes_gpc' setting, an
unauthenticated, remote attacker can leverage this issue to launch SQL
injection attacks against the affected application, including the
discovery of password hashes of WordPress users.");
  script_set_attribute(attribute:"see_also", value:"http://www.waraxe.us/advisory-50.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/May/316");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/23");

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
include("url_func.inc");
include("install_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Try to exploit the flaw to generate a SQL error.
exploit = "'" + SCRIPT_NAME;
# nb: this works as long as the USER_COOKIE and PASS_COOKIE are
#     derived from COOKIEHASH / site url as in wp-settings.php.
site = "http://" + get_host_name();
if (port != 80) site = site + ":" + port;
if (strlen(dir)-1 == '/') dir = substr(dir, 0, strlen(dir)-2);
site = site + dir;
cookiehash = hexstr(MD5(site));

# nb: we need to encode (twice) the single quote.
cookie = urlencode(
  str        : exploit,
  unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!~*()-]/"
);
cookie =
  "wordpressuser_" + cookiehash + "=" + cookie + "; " +
  "wordpresspass_" + cookiehash + "=x";

u = dir + "/wp-admin/admin-ajax.php?cookie=" + urlencode(str:cookie);
r = http_send_recv3(method: "GET", port:port, item: u, exit_on_fail: TRUE);

# There's a problem if we see an error involving our exploit for the user name.
if ("WordPress database error" >< r[2])
{
  res2 = str_replace(find:"&#039;", replace:"'", string:r[2]);
  if (" WHERE user_login = '" + exploit + "'</code>" >< res2)
  {
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    security_hole(port);
    exit(0);
  }
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
