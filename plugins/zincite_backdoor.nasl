#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(14184);
 script_version ("$Revision: 1.8 $");
 script_cvs_date("$Date: 2015/10/21 20:34:21 $");

 script_name(english:"Zincite.A (MyDoom.M) Backdoor Detection");
 script_summary(english:"Detect MyDoom worm");
 
 script_set_attribute(attribute:"synopsis", value:"The remote host may 
have been compromised by a worm.");
 script_set_attribute(attribute:"description", value:
"The backdoor 'BackDoor.Zincite.A' is installed on the remote host. 
It has probably been installed by the 'MyDoom.M' virus.  This 
backdoor may allow an attacker to gain unauthorized access on the 
remote host.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b1ba661");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?031b6a24");
 script_set_attribute(attribute:"solution", value:"Verify if the remote host has been compromised, and reinstall
 the system if necessary.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/02");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");
 script_require_ports(1034);
 exit(0);
}


port = 1034;
if ( get_port_state(port) ) 
 {
	req = raw_string(0xc7);
	soc = open_sock_tcp(port);
	if ( soc ) 
	{
	send(socket:soc, data:req);
	r = recv(socket:soc, length:255, timeout:3);
        if ( raw_string(0x92, 0x3a, 0x6c) >< r && strlen(r) == 255 )	
	 security_hole(port);

	}
 }

