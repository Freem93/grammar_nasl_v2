#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/15/009)

include("compat.inc");

if(description)
{
 script_id(11728);
 script_version ("$Revision: 1.21 $");

 script_cve_id("CVE-2000-0826");
 script_bugtraq_id(1657);
 script_osvdb_id(13326);

 script_name(english:"Mobius DocumentDirect ddicgi.exe Long GET Request Overflow");
 script_summary(english: "Checks for the ddicgi.exe file");
 
 script_set_attribute(attribute:"synopsis", value:
"It might be possible to execute arbitrary code on the remote server.");
 script_set_attribute(attribute:"description", value:
"The file 'ddicgi.exe' exists on this web server.  Some versions of this
file are vulnerable to remote exploit. 

An attacker may use this file to gain access to confidential data or
escalate their privileges on the web server. 

** It seems that Nessus crashed your web server.");
 script_set_attribute(attribute:"see_also", value:
"http://seclists.org/bugtraq/2000/Sep/184");
 script_set_attribute(attribute:"solution", value:
"Remove it from the cgi-bin or scripts directory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"vuln_publication_date", value:
"2000/09/08");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2003/06/11");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2003-2016 John Lampe");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

if (! is_cgi_installed_ka(item:"/ddrint/bin/ddicgi.exe", port:port)) exit(0);
if(http_is_dead(port:port))exit(0);

req = strcat('GET /ddrint/bin/ddicgi.exe?', crap(1553), '=X HTTP/1.0\r\n\r\n');
soc = open_sock_tcp(port);
if (! soc) exit(0);
send(socket:soc, data:req);
r = http_recv(socket:soc);
close(soc);

if(http_is_dead(port:port, retry: 3)) security_hole(port);


