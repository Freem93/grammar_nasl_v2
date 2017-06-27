#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#


include("compat.inc");

if(description)
{
 script_id(11045);
 script_cve_id("CVE-2002-1974");
 script_bugtraq_id(5200);
 script_osvdb_id(848);
 script_version ("$Revision: 1.15 $");

 script_name(english:"Zaurus PDA FTP Server Unpassworded root Account");
 script_summary(english:"Logs into the remote Zaurus FTP server");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server has an account with a blank password." );
 script_set_attribute(attribute:"description", value:
"The remote Zaurus FTP server can be accessed as the user 'root' with
no password. An attacker may use this flaw to steal or modify the
content of your PDA, including (but not limited to) your address book,
personal files, and list of appointments." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Jul/93" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/07/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/07/10");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_require_ports(4242);
 exit(0);
}

#
# The script code starts here : 
#

include('ftp_func.inc');
port = 4242;
if(!port)port = 21;

state = get_port_state(port);
if(!state)exit(0);
soc = open_sock_tcp(port);
if(soc)
{
 r = ftp_authenticate(socket:soc, user:"root", pass:"");
 if(r)
 {
  security_hole(port);
 }
 close(soc);
}
