#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34419);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2008-4645");
  script_bugtraq_id(31762);
  script_osvdb_id(49161);
  script_xref(name:"EDB-ID", value:"6755");

  script_name(english:"PhpWebGallery comments.php sort_by Parameter SQL Injection");
  script_summary(english:"Tries to generate a SQL syntax error");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PhpWebGallery, an open source photo gallery
application written in PHP. 

The installed version of PhpWebGallery fails to sanitize user-supplied
input to the 'sort_by' parameter of the 'comments.php' script before
using it in a database query.  Regardless of PHP's 'magic_quotes_gpc'
setting, an unauthenticated, remote attacker can leverage this issue to
manipulate SQL queries and uncover sensitive information from the
application's database. 

Note that this issue reportedly can be leveraged to obtain an admin
session and in turn gain administrative access to the application and
possibly execute arbitrary code through the affected web server,
although Nessus has not tested for this explicitly." );
  # http://piwigo.org/doc/doku.php#release_1.7.3
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a1a1fac" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PhpWebGallery 1.7.3 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/15");
 script_cvs_date("$Date: 2016/05/20 14:30:35 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpwebgallery:phpwebgallery");
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
if (thorough_tests) dirs = list_uniq(make_list("/phpwebgallery", "/gallery", "/webgallery", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to generate a SQL syntax error.
  url = string(dir, "/comments.php?sort_by=", SCRIPT_NAME);

  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);

  # There's a problem if we see a SQL error with our script name.
  if (
    "mysql error " >< res &&
    string("ORDER BY ", SCRIPT_NAME, " DESC") >< res
  )
  {
    security_hole(port);
    exit(0);
  }
}
