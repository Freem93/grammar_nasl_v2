#
# This script was written by Geoff Humes <geoff.humes@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (9/2/09)
# - Revised plugin title (10/29/09)

include("compat.inc");

if(description)
{
	script_id(11203);
	script_version("$Revision: 1.10 $");
	script_cvs_date("$Date: 2012/08/15 21:05:11 $");

	script_cve_id("CVE-1999-0508");

	script_name(english:"Motorola Vanguard with No Password (telnet check)");
	script_summary(english:"Attempts to log into Vanguards.");
 

	script_set_attribute(attribute:"synopsis", value:
"The router does have a password.");
	script_set_attribute(attribute:"description", value:
"This device is a Motorola Vanguard router and has no password set.  An
attacker can reconfigure this device without providing any
authentication.");
script_set_attribute(attribute:"solution", value:
"Please set a strong password for this device.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SNMP Community Scanner');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
	script_set_attribute(attribute:"plugin_publication_date", value:
"2003/01/22");
	script_set_attribute(attribute:"plugin_type", value:"remote");
	script_end_attributes();

	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2003-2012 Digital Defense");
	script_family(english:"Misc.");
	script_require_ports(23);
 
	exit(0);
}

include('telnet_func.inc');

function greprecv(socket, pattern)
{
 local_var buffer, cnt, _r;
 buffer = "";
 cnt = 0;
 while(1)
 {
  _r = recv_line(socket:socket, length:4096);
  if(strlen(_r) == 0)return(0);
  buffer = string(buffer, _r);
  if(ereg(pattern:pattern, string:_r))return(buffer);
  cnt = cnt + 1;
  if(cnt > 1024)return(0);
 }
}

#
# The script code starts here
#
port = 23;


if(get_port_state(port))
{
	banner = get_telnet_banner(port:port);
	if ( ! banner || "OK" >!< banner ) exit(0);

	soc = open_sock_tcp(port);
	if(soc)
	{
		buf = greprecv(socket:soc, pattern:".*OK.*");
		if(!buf)exit(0);
		send(socket:soc, data:string("atds0\r\n"));
		buf = greprecv(socket:soc, pattern:".*Password.*");
		if(!buf)exit(0);
		send(socket:soc, data:string("\r\n"));
		buf = greprecv(socket:soc, pattern:".*Logout.*");
		if(buf)security_hole(port);
		close(soc);
	}
}
