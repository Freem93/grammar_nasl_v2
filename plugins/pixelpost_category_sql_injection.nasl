#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21645);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2006-2889");
  script_bugtraq_id(18276);
  script_osvdb_id(26604);

  script_name(english:"Pixelpost index.php category Parameter SQL Injection");
  script_summary(english:"Tries to exploit SQL injection issue in Pixelpost");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Pixelpost, a photo blog application based
on PHP and MySQL. 

The version of Pixelpost installed on the remote fails to sanitize
user-supplied input to the 'category' parameter of the 'index.php'
script before using it to construct database queries.  Provided PHP's
'magic_quotes_gpc' setting is disabled, an unauthenticated attacker
can exploit this flaw to manipulate database queries and, for example,
uncover the administrator's username and password hash, which can
later be used to gain administrative access to the affected
application. 

In addition, Pixelpost reportedly suffers from a similar issue
involving the 'archivedate' parameter of the 'index.php' script,
although Nessus has not checked for it." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/435856/30/60/threaded" );
  # http://web.archive.org/web/20070326112357/http://forum.pixelpost.org/showthread.php?t=4331
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8952247d" );
 script_set_attribute(attribute:"solution", value:
"Apply the patches listed in the vendor forum post referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/06/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/03");
 script_cvs_date("$Date: 2012/12/14 22:51:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:pixelpost:pixelpost");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

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

foreach dir (dirs) {
  # Try to exploit the flaw.
  now = unixtime();
  exploit = string("UNION SELECT '1','2','", SCRIPT_NAME, "','", now, "','5'--");
  r = http_send_recv3(method:"GET", 
    item:string(
      dir, "/index.php?",
      "x=browse&",
      "category='", urlencode(str:exploit)
    ),
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if the time is used in the thumbnail name and 
  # our script name for an alt tag.
  if (string("<img src='thumbnails/thumb_", now, "' alt='", SCRIPT_NAME) >< res)
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
