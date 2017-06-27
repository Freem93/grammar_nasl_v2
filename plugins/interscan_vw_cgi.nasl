#
# This script was written by Gregory Duchemin <plugin@intranode.com>
#
# See the Nessus Scripts License for details
#
# Title: Interscan VirusWall Remote configuration Vulnerability.
#
# Changes by Tenable:
# - Revised english plugin title, updated copyright, added osvdb ref (1/13/2009)
# - Revised plugin title (5/24/2012)
# - Updated copyright (5/29/2012)

#### REGISTER SECTION ####


include("compat.inc");

if(description)
{
 script_id(10733);
 script_bugtraq_id(2579);
 script_osvdb_id(607);
 script_cve_id("CVE-2001-0432");
 script_version ("$Revision: 1.25 $");

#Name used in the client window.

script_name(english:"Trend Micro InterScan VirusWall /interscan/cgi-bin/FtpSave.dll Unauthenticated Remote Configuration Manipulation");


 script_set_attribute(attribute:"synopsis", value:
"A remote service may be reconfigured by unauthorized users.");
 script_set_attribute(attribute:"description", value:
"The management interface used with the Interscan VirusWall 
uses several cgi programs that may allow a malicious user to remotely 
change the configuration of the server without any authorization using 
maliciously constructed querystrings." );
 # https://web.archive.org/web/20020227081400/http://archives.neohapsis.com/archives/bugtraq/2001-04/0218.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9986ffc0" );
 script_set_attribute(attribute:"solution", value:
"Filter access to the management interface from the internet." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/08/23");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/04/13");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();





#Summary appearing in the tooltips, only one line. 

summary["english"]="Check if the remote Interscan is vulnerable to remote reconfiguration.";
script_summary(english:summary["english"]);


#Test it among the firsts scripts, no risk to harm the remote host.

script_category(ACT_GATHER_INFO);

#Copyright stuff

script_copyright(english:"Copyright (C) 2001-2016 INTRANODE");


 
#Category in wich script must be stored.

family["english"]="CGI abuses";
script_family(english:family["english"]);


script_dependencie("http_version.nasl");


#optimization, stop here if either no web service was found by find_service1.nasl plugin or no port 80 was open.

script_require_ports(80, "Services/www");
 
exit(0);
}




#### ATTACK CODE SECTION ####



include("http_func.inc");
include("http_keepalive.inc");
#search web port in knowledge database

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


request = http_get(item:"/interscan/cgi-bin/FtpSave.dll?I'm%20Here", port:port);
receive = http_keepalive_send_recv(port:port, data:request);

signature = "These settings have been saved";

if (signature >< receive)
{
 security_hole(port);
}

