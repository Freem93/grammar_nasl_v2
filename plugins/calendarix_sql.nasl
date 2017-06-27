#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#
# Fixed by Tenable:
#  - added CVE xref.
#  - added BID 13825,
#  - added OSVDB xrefs.
#  - added link to original advisory.


include("compat.inc");

if(description)
{
 script_id(18410);
 script_version ("$Revision: 1.17 $");

 script_cve_id("CVE-2005-1865", "CVE-2005-1866");
 script_bugtraq_id(13825, 13826);
 script_osvdb_id(16971, 16972, 16973, 16974, 16975);

 script_name(english:"Calendarix Multiple Vulnerabilities (SQLi, XSS)");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Calendarix, a PHP-based calendar system. 

The remote version of this software is prone to a remote file include
vulnerability as well as multiple cross-site scripting, and SQL
injection vulnerabilities.  Successful exploitation could result in
execution of arbitrary PHP code on the remote site, a compromise of
the application, disclosure or modification of data, or may permit an
attacker to exploit vulnerabilities in the underlying database
implementation." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/May/355" );
 script_set_attribute(attribute:"see_also", value:"http://www.calendarix.com/download_advanced.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.6.20051111 which fixes this issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/28");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for multiple vulnerabilities in Calendarix";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
  
 script_copyright(english:"Copyright (C) 2005-2016 Josh Zlatin-Amishav");
 
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

global_var port;
port = get_http_port(default:80);


if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

function check(url)
{
 local_var r, req;

 req = http_get(item:string(url, "/cal_week.php?op=week&catview=999'"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( r == NULL ) exit(0);
 if ( 'mysql_num_rows(): supplied argument is not a valid MySQL result' >< r )
 {
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(url:dir);
}
