#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#
# Fixed by Tenable:
#   - added See also.
#   - Revised plugin title (12/23/2008)


include("compat.inc");

if(description)
{
 script_id(19391);
 script_version ("$Revision: 1.15 $");

 script_cve_id("CVE-2003-0509");
 script_bugtraq_id(14101, 14103, 14112);
 script_osvdb_id(10098, 10099, 10100);

 script_name(english:"Cyberstrong eShop Multiple Script ProductCode Parameter SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is affected by
multiple SQL injection flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Cyberstrong eShop, a shopping cart written
in ASP. 

The remote version of this software contains several input validation
flaws leading to SQL injection vulnerabilities.  An attacker may
exploit these flaws to affect database queries, possibly resulting in
disclosure of sensitive information (for example, the admin's user and
password) and attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Jul/3" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/30");
 script_cvs_date("$Date: 2016/10/10 15:57:04 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 summary["english"] = "Checks for a SQL injection in Cyberstrong eShop v4.2";

 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);

 script_family(english:"CGI abuses");
 script_copyright(english:"Copyright (C) 2005-2016 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/ASP");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port)) exit(0);

global_var port;

function check(url)
{
 local_var req, res;

 req = http_get(item:url +"/20Review.asp?ProductCode='", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( res == NULL ) exit(0);
 if ( 'Microsoft OLE DB Provider for ODBC Drivers' >< res && 'ORDER BY TypeID' >< res )
 {
        security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
        exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
  check(url:dir);
}
