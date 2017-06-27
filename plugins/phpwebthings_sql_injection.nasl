#
# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#

# Changes by Tenable:
# - Revised plugin title, added additional OSVDB refs (4/24/009)


include("compat.inc");

if (description) {
script_id(20170);
script_version("$Revision: 1.22 $");

script_cve_id("CVE-2005-3585", "CVE-2005-4218");
script_bugtraq_id(15276, 15465);
script_osvdb_id(
  20441, 
  21650, 
  21651, 
  21652,
  21653, 
  21654, 
  21655, 
  21656
 );

script_name(english:"phpWebThings Multiple Scripts SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the phpWebThings application framework. 

The version of phpWebThings installed on the remote host does not
properly sanitize user input in the 'forum' and 'msg' parameters of
'forum.php' script before using it in database queries.  An attacker
can exploit this vulnerability to display the usernames and passwords
(md5 hash) from the website and then use this information to gain
administrative access to the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Nov/56" );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/phpwebth14_xpl.html" );
 # http://web.archive.org/web/20080926131718/http://www.ojvweb.nl/download.php?file=64&cat=17&subref=10
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57b75952" );
 script_set_attribute(attribute:"solution", value:
"Apply the phpWebthings 1.4 forum patch referenced in the third URL
above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/11/03");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/11/07");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpwebthings:phpwebthings");
script_end_attributes();


script_summary(english:"Check if phpWebThings is vulnerable to SQL Injection attacks");
script_category(ACT_ATTACK);
script_family(english:"CGI abuses");
script_copyright(english:"This script is Copyright (C) 2005-2016 Ferdy Riphagen");
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
include("url_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = list_uniq(make_list("/phpwebthings", "/webthings", "/phpwt", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  exploit = "-1 UNION SELECT null,123456,null,null,null,null--";
  req = http_get(item:string(dir, "/forum.php?forum=", urlencode(str:exploit)), port:port);
  recv = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if(recv == NULL)exit(0);

  if (
    string('<input type="hidden" value="', exploit, '" name="sforum"') >< recv &&
    egrep(pattern:"created with <a href=[^>]+.*>phpWebThings", string:recv)
  ) {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
   exit(0);
  }
}
