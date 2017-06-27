#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22902);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2006-5629");
  script_bugtraq_id(20661);
  script_osvdb_id(30156, 30157);

  script_name(english:"Hosting Controller Multiple Script ForumID Parameter SQL Injection");
  script_summary(english:"Checks for a SQL injection flaw in Hosting Controller");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is susceptible
to a SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The installed version of Hosting Controller fails to sanitize input to
the 'ForumID' parameter of the 'forum/HCSpecific/EnableForum.asp'
script before using it in database queries.  An unauthenticated
attacker may be able to leverage this issue to manipulate database
queries to reveal sensitive information, modify data, launch attacks
against the underlying database, etc. 

In addition, the 'DisableForum.asp' script is also vulnerable." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?954337d8" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80267a16" );
 script_set_attribute(attribute:"solution", value:
"Apply the Post Hotfix 3.3 Security Patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/10/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/10/25");
 script_cvs_date("$Date: 2011/03/12 01:05:15 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8077);
  script_require_keys("www/ASP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8077, embedded: 0);
if (!can_host_asp(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/hc", "/hosting_controller", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  exploit = string("'", SCRIPT_NAME);
  r = http_send_recv3(method:"GET", 
    item:string(
      dir, "/forum/HCSpecific/EnableForum.asp?",
      "action=enableforum&",
      "ForumID=", exploit
    ),
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    string("query expression 'ForumID='", SCRIPT_NAME) >< res &&
    egrep(pattern:"Microsoft OLE DB Provider for ODBC Drivers.+error '80040e14'", string:res)
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
