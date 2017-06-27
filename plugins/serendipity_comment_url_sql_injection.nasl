#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60097);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_cve_id("CVE-2012-2762");
  script_bugtraq_id(53620);
  script_osvdb_id(82036);

  script_name(english:"Serendipity comment.php url Parameter SQL Injection");
  script_summary(english:"Checks for SQL injection in comments.php.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a SQL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Serendipity installed on the remote host is
affected by a SQL injection vulnerability because the
'include/functions_trackbacks.inc.php' script does not properly
sanitize user-supplied input passed via the 'url' parameter to the
'comment.php' script.  Provided that PHP's 'magic_quotes_gpc' setting
is disabled, this may allow an attacker to inject or manipulate SQL
queries in the back-end database, allowing for the manipulation or
disclosure of arbitrary data.");
  script_set_attribute(attribute:"see_also", value:"https://www.htbridge.com/advisory/HTB23092");
  script_set_attribute(attribute:"see_also", value:"http://blog.s9y.org/archives/241-Serendipity-1.6.2-released.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Serendipity 1.6.1 SQL Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:s9y:serendipity");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("serendipity_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/serendipity");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "serendipity", 
  port         : port, 
  exit_on_fail : TRUE
);
dir = install["dir"];

sql_test = "1' OR '1'='1";
url = dir + "/comment.php?type=trackback&entry_id=1&url=" + 
      urlencode(str:sql_test);

res = http_send_recv3(
  method       : "GET", 
  item         : url, 
  port         : port, 
  exit_on_fail : TRUE
);

if (
  "<error>1</error>" >< res[2] && 
  "<message>Danger Will Robinson, trackback failed.</message>" >< res[2]
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  report = NULL;
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to exploit the issue using the following URL :' +
      '\n' +
      '\n' + build_url(port:port, qs:url) +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Serendipity", build_url(qs:dir+"/", port:port));
