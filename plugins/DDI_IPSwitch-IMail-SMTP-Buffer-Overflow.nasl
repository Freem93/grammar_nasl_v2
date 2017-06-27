#
# This script is Copyright (C) Digital Defense Inc.
# Author: Forrest Rae <forrest.rae@digitaldefense.net>
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised description, added CVSS, updated severity (4/10/2009)


include("compat.inc");

if(description)
{
	script_id(10994);
	script_version ("$Revision: 1.22 $");

	script_cve_id("CVE-2001-0039","CVE-2001-0494");
	script_bugtraq_id(2083, 2651);
	script_osvdb_id(1686, 5610);
 
 	script_name(english:"IPSwitch IMail SMTP Multiple Vulnerabilities (OF, DoS)");
	script_summary(english:"IPSwitch IMail SMTP Buffer Overflow");
 
	script_set_attribute(attribute:"synopsis", value:
"It may be possible to execute arbitrary commands on the remote
system.");
	script_set_attribute(attribute:"description", value:
"A vulnerability exists within IMail that allows remote attackers to
gain SYSTEM level access to servers running IMail's SMTP daemon
(versions 6.06 and below).  The vulnerability stems from the IMail
SMTP daemon not doing proper bounds checking on various input data
that gets passed to the IMail Mailing List handler code.  If an
attacker crafts a special buffer and sends it to a remote IMail SMTP
server, it is possible that an attacker can remotely execute code
(commands) on the IMail system." );
	# https://web.archive.org/web/20011109230429/http://archives.neohapsis.com/archives/bugtraq/2001-04/0433.html
	script_set_attribute(attribute:"see_also",value:
"http://www.nessus.org/u?ff8d9b9d" );
	script_set_attribute(attribute:"solution", value:
"Apply vendor-supplied patches." );
	script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
	script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
	script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
	script_set_attribute(attribute:"exploit_available", value:"true");
	script_set_attribute(attribute:"plugin_publication_date", value:
"2002/06/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/12/07");
 script_cvs_date("$Date: 2016/12/06 20:03:50 $");
	script_set_attribute(attribute:"plugin_type", value:"remote");
	script_end_attributes();

	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2002-2016 Digital Defense, Inc.");
	script_family(english:"SMTP problems");
	script_dependencie("find_service1.nasl");
	script_require_ports(25);
	exit(0);
}

debug = 0;
ddidata = string("Not Applicable");
port = 25;

if(get_port_state(port))
{
	if(debug == 1) { display("Port ", port, " is open.\n"); }
		

	soc = open_sock_tcp(port);
	if(soc)
	{
		if(debug == 1)
		{
			display("Socket is open.\n");
		}
		
		banner = recv_line(socket:soc, length:4096);
		
		if(debug == 1)
		{
			display("\n---------Results from request ---------\n");
			display(banner);
			display("\n---------End of Results from request ---------\n\n");
		}
		     
		if(
		   egrep(pattern:"IMail 6\.0[1-6] ", string:banner) 	|| 
		   egrep(pattern:"IMail 6\.0 ", string:banner) 		||
		   egrep(pattern:"IMail [1-5]\.", string:banner)
		  )
		{
			if(debug == 1)
			{
				display("SMTP Server is IMail\n");
			}
		
			security_hole(port); 
			exit(0);
		}

		close(soc);
	}
	else
	{
		if(debug == 1) { display("Error: Socket didn't open.\n"); }
	}
}



