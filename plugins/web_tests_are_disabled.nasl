#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(43067);
 script_version("$Revision: 1.6 $");
 script_cvs_date("$Date: 2011/08/12 12:43:54 $");

 script_name(english:"Web Application Tests Disabled");
 
 script_set_attribute(attribute:"synopsis", value:
"Web application tests were not enabled during the scan." );
 script_set_attribute(attribute:"description", value:
"One or several web servers were detected by Nessus, but neither the
CGI tests nor the Web Application Tests were enabled. 

If you want to get a more complete report, you should enable one of 
these features, or both.

Please note that the scan might take significantly longer with these
tests, which is why they are disabled by default." );
 script_set_attribute(attribute:"solution", value:
"To enable specific CGI tests, go to the 'Preferences' tab, select
'Global variable settings' and set 'Enable CGI scanning'. 

To generic enable web application tests, go to the 'Preferences' tab,
select 'Web Application Tests Settings' and set 'Enable web
applications tests'. 

You may configure other options, for example HTTP credentials in
'Login configurations', or form-based authentication in 'HTTP login
page'." );
 script_set_attribute(attribute:"see_also", value: "http://blog.tenablesecurity.com/web-app-auditing/");
 script_set_attribute(attribute:"risk_factor", value: "None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/09");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english: "Check that CGI or web application tests are enabled");
 script_category(ACT_END);
 
 script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencies("http_version.nasl", "global_settings.nasl", "web_app_test_settings.nasl", "embedded_web_server_detect.nasl", "broken_web_server.nasl", "www_default_page.nasl");
 script_require_ports("Services/www");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

exit(0); # Useless now that we have the 'webapp.pol' policy

list = get_kb_list("Success/*");
if ( isnull(list) ) exit(0, "No script finished (dead host?).");


l = get_kb_list("Services/www");
if (isnull(l)) exit(0, "No web servers were detected.");
l = make_list(l);
if (max_index(l) == 0) exit(0, "No web servers were detected.");

z = int(get_kb_item("Settings/HTTP/max_run_time"));
if (z > 0) exit(0, "Wep application tests were already enabled.");
z = get_kb_item("Settings/disable_cgi_scanning");
if (! z) exit(0, "CGI scanning was already enabled.");

n = 0;
foreach port (l)
{
  # Ignore unconfigured web servers
  z = get_kb_item("www/"+port+"/default_page");
  if (z) continue;
  # Ignore broken web servers
  z = get_kb_item("Services/www/" +port+ "/broken");
  if (z) continue;
  # Ignore embedded web servers
  z = get_kb_item("Services/www/" + port + "/embedded");
  if (z) continue;
  n ++;
}

if (n == 0) exit(0, "All web servers are unconfigured, broken or embedded.");

security_note(port: 0);
