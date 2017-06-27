# Cisco VG248 with a blank password nasl script. - non intrusive
# This script was written by Rick McCloskey <rpm.security@gmail.com>
# 
# Tested against production systems with positive results. 
# This cisco unit does not respond to the other "Cisco with no password" 
# nasl scripts.
#
# This script is released under GPL
#


include("compat.inc");

if(description)
{
   script_id(19377);
   script_version ("$Revision: 1.8 $");
   script_cvs_date("$Date: 2013/01/25 01:19:07 $");
   
   script_name(english:"Cisco VG248 Unpassworded Account");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an account with a blank password." );
 script_set_attribute(attribute:"description", value:
"The remote host is a Cisco VG248 with a blank password.

The Cisco VG248 does not have a password set and allows direct
access to the configuration interface. An attacker could telnet 
to the Cisco unit and reconfigure it to lock the owner out as 
well as completely disable the phone system." );
 script_set_attribute(attribute:"solution", value:
"Telnet to this unit and at the configuration interface: 
Choose Configure-> and set the login and enable passwords. If 
possible, in the future do not use telnet since it is an insecure 
protocol." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/04");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
   summary["english"] = "The remote host is a Cisco VG248 with a blank password.";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2005-2013 Rick McCloskey");
   script_family(english:"CISCO");
   script_require_ports("Services/telnet", 23);
   exit(0);
}

include('telnet_func.inc');
port = get_kb_item("Services/telnet");
if ( ! port ) port = 23;
if ( ! get_port_state(port)) exit (0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if ( ! soc ) exit (0);
 banner = telnet_negotiate(socket:soc);
 banner += line = recv_line(socket:soc, length:4096);
 n  = 0;
 while( line =~ "^ ")
	{
   		line = recv_line(socket:soc, length:4096);
		banner += line;
		n ++;
		if ( n > 100 ) exit(0); # Bad server ?
	}
   close(soc);
   if ( "Main menu" >< banner && "Configure" >< banner && "Display" >< banner )
	{
		security_hole(port);
	}
 
}

