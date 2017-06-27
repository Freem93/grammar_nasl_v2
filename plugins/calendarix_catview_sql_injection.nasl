#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34202);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2008-2429");
  script_bugtraq_id(30817);
  script_osvdb_id(47740);
  script_xref(name:"Secunia", value:"30710");

  script_name(english:"Calendarix Basic cal_cat.php catview Parameter SQL Injection");
  script_summary(english:"Tries to manipulate a category listing");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Calendarix, a free, web-based calendar
application written in PHP. 

The installed version of Calendarix does not validate user-supplied
input to the 'catview ' parameter of the 'cal_cat.php' script before
using it in database queries.  Regardless of PHP's 'magic_quotes_gpc'
setting, an unauthenticated, remote attacker can leverage this issue to
manipulate SQL queries and, for example, uncover sensitive information
from the application's database or possibly execute arbitrary PHP
code. 

Note that there may also be another SQL injection vulnerability in
this version of Calendarix, one involving the 'catsearch' parameter of
the 'cal_search.php' script, although Nessus has not tested for it
explicitly." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-28/" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/495704/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 0.8.20080808 or later as that reportedly addresses
the vulnerability." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/14");
 script_cvs_date("$Date: 2012/11/29 23:28:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:calendarix:basic");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2012 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/calendarix", "/calendar", cgi_dirs()));
else dirs = make_list(cgi_dirs());

info = "";
foreach dir (dirs)
{
  # Try to exploit the issue to manipulate a category listing.
  magic = unixtime();
  exploit = string("1 UNION SELECT 1,", magic);
  url = string(
    dir, "/cal_cat.php?",
    "op=cats&",
    "year=2008&",
    "catview=", str_replace(find:" ", replace:"+", string:exploit)
  );

  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);

  # There's a problem if we see our magic in the category list.
  if (
    string(">", magic, "</a> &nbsp; &nbsp; (0 events") >< res ||
    (
      'Alt="About Caledarix ' >< res ||
      "Vincent Hor',FGCOLOR" >< res
    )
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
