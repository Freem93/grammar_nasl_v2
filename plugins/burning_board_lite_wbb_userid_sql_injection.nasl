#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(23734);
  script_version ("$Revision: 1.16 $");

  script_cve_id("CVE-2006-6289");
  script_bugtraq_id(21265);
  script_osvdb_id(36906);

  script_name(english:"WoltLab Burning Board Lite wbb_userid Parameter PHP Unset SQL Injection");
  script_summary(english:"Checks for SQL injection vulnerability in Burning Board Lite");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote version of Burning Board Lite fails to sanitize input to
the 'wbb_userid' parameter before using it in a database query. 
Provided PHP's 'register_globals' setting is enabled and
'magic_quotes_gpc' setting is disabled, an unauthenticated attacker
may be able to leverage this issue to uncover sensitive information
(such as password hashes), modify existing data, or launch attacks
against the underlying database." );
 # https://web.archive.org/web/20070216223158/http://retrogod.altervista.org/wbblite_102_sql.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?554a9943");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/11/25");
 script_cvs_date("$Date: 2017/05/02 23:36:52 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("burning_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

init_cookiejar();

# Test any installs.
install = get_kb_list(string("www/", port, "/burning_board_lite"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to cause a SQL error.
  set_http_cookie(name: "wbb_userpassword", value: 0);
  r = http_send_recv3(port:port, method: 'POST', item: dir +"/", version: 11,
 data: strcat("wbb_userid=%27", SCRIPT_NAME, "&-246470575=1&-73279541=1"),
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));

  if (isnull(r)) exit(0);

  # There's a problem if we see a database error with our script name.
  res = r[1]+r[2];
  if (
    "SQL-DATABASE ERROR" >< res &&
    string("WHERE userid = ''", SCRIPT_NAME) >< res
  ) {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }  
}
