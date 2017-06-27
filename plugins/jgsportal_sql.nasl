#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised plugin title, added CVE/OSVDB refs (1/13/2009)


include("compat.inc");

if(description)
{
 script_id(18289);
 script_version ("$Revision: 1.14 $");
 script_cvs_date("$Date: 2014/04/23 16:29:27 $");

 script_cve_id("CVE-2005-1633", "CVE-2005-1634");
 script_bugtraq_id(13650);
 script_osvdb_id(
  16665,
  16666,
  16667,
  16668,
  16669,
  16670,
  16671,
  16672,
  16673,
  16674,
  16675,
  16676,
  16677,
  16678,
  16679,
  16680,
  16681
 );

 script_name(english:"JGS-Portal for WoltLab Burning Board Multiple Vulnerabilities (SQLi, XSS)");
 script_summary(english:"JGS-Portal Multiple XSS and SQL injection Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web application is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the JGS-Portal, a web portal written in PHP.

The remote version of this software contains an input validation flaw leading
to multiple SQL injection and cross-site scripting vulnerabilities. An attacker
may exploit these flaws to execute arbitrary SQL commands against the remote
database and to cause arbitrary code execution for third-party users." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/16");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_family(english:"CGI abuses");
 script_copyright(english:"Copyright (C) 2005-2014 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("http_func.inc");
include("global_settings.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

function check(url)
{
 local_var req, res;

 req = http_get(item:url + "/jgs_portal_statistik.php?meinaction=themen&month=1&year=1'", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if (("SQL-DATABASE ERROR" >< res ) && ("SELECT starttime FROM bb1_threads WHERE FROM_UNIXTIME" >< res ))
 {
     security_hole(port);
     set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
     exit(0);
 }
}

foreach dir ( make_list (cgi_dirs()) )
{
  check(url:dir);
}
