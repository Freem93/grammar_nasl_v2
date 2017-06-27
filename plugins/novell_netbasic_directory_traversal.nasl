#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, output formatting (9/3/09)


include("compat.inc");

if(description)
{
  script_id(12050);
  script_version ("$Revision: 1.17 $");
  script_cve_id("CVE-2002-1417");
  script_bugtraq_id(5523);
  script_osvdb_id(8943);

  script_name(english:"Novell NetBasic Scripting Server Encoded Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is vulnerable to information disclosure." );
 script_set_attribute(attribute:"description", value:
"Novell Netbasic Scripting Server Directory Traversal

It is possible to escape out of the root directory of the scripting server by 
substituting a forward or backward slash for %5C. As a result, system 
information, such as environment and user information, could be obtained from 
the NetWare server.

Example: http://server/nsn/..%5Cutil/userlist.bas" );
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch and remove all default files from their 
respective directories." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/08/20");
 script_set_attribute(attribute:"patch_publication_date", value: "2002/08/13");
 script_cvs_date("$Date: 2013/04/10 21:55:02 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for Novell Netbasic Scripting Server Directory Traversal Vulnerability");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 David Kyger");
 script_family(english:"Netware");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

function check(req)
{
 http = http_get(item:req, port:port);
 res = http_keepalive_send_recv(port:port, data:http);
 if ( res == NULL ) exit(0);
 pattern = "Error running script";
 pattern2 = "Module load Failed";

 if((pattern >!< r) && (pattern2 >!< r)) {
	# Work around some 'smart' modules
 	http = http_get(item:req + 'foo', port:port);
 	res = http_keepalive_send_recv(port:port, data:http);
 	if ( res == NULL ) exit(0);
	if ( egrep(pattern:"^HTTP/.* 200 .*", string:res) ) return 0;
        else return(1);
        }
 return(0);
}

flag = 0;

warning = "
The following Novell scripts can be executed on the server:";

port = get_http_port(default:80);

if(get_port_state(port)) {

        pat1 = "Statistics for volume";
        pat2 = "used by files";
        pat3 = "Novell Script For NetWare";
        pat4 = "Directory Of";
        pat5 = "====================================================";
        pat6 = "User:";
        pat7 = "Media Type";
        pat8 = "Interrupt Secondary";
        pat9 = "SYS:NSN\\WEB\\";
        pat10 = "SYS:NSN\\TEMP\\";
        pat11 = "NOT-LOGGED-IN"; 
        pat12 = "--------------";
        pat13 = "ADMSERV_ROOT";
        pat14 = "ADMSERV_PWD";
        pat15 = "Directory Listing Tool";
        pat16 = "Server Name";

	fl[0] = "/nsn/..%5Cutil/chkvol.bas";
	fl[1] = "/nsn/..%5Cutil/dir.bas";
	fl[2] = "/nsn/..%5Cutil/glist.bas";
	fl[3] = "/nsn/..%5Cutil/lancard.bas";
	fl[4] = "/nsn/..%5Cutil/set.bas";
	fl[5] = "/nsn/..%5Cutil/userlist.bas";
	fl[6] = "/nsn/..%5Cweb/env.bas";
	fl[7] = "/nsn/..%5Cwebdemo/fdir.bas"; 

   for(i=0;fl[i];i=i+1) {
   req = http_get(item:fl[i], port:port);
   buf = http_keepalive_send_recv(port:port, data:req);
    if ( buf == NULL ) exit(0);
    if ((pat1 >< buf && pat2 >< buf) || (pat3 >< buf && pat4 >< buf) || (pat5 >< buf && pat6 >< buf) || (pat7 >< buf && pat8 >< buf) || (pat9 >< buf && pat10 >< buf) || (pat11 >< buf && pat12 >< buf) || (pat13 >< buf && pat14 >< buf) || (pat15 >< buf && pat16 >< buf)) {
	warning = warning + string("\n", fl[i]);
        flag = 1;
	}
    }
    if (flag > 0) {
        security_warning(port:port, extra:warning);
    } else {
      exit(0);
      }
}


