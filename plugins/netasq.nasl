#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14378);
 script_version("$Revision: 1.9 $");
 script_cvs_date("$Date: 2011/11/28 21:39:46 $");

 script_name(english:"NetAsq IPS-Firewalls Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is an IPS/firewall." );
 script_set_attribute(attribute:"description", value:
"It is very likely that this remote host is a NetAsq IPS-Firewalls
with port TCP/1300 open to allow Firewall Manager tool to remotely 
configure it.

Letting attackers know that you are using a NetAsq will help them to 
focus their attack or will make them change their strategy. 

You should not let them know such information." );
 script_set_attribute(attribute:"see_also", value:"http://www.netasq.com" );
 script_set_attribute(attribute:"solution", value:
"Do not allow any connection on the firewall itself, except from trusted
network." );
 script_set_attribute(attribute:"risk_factor", value:"Low" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/26");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determines if the remote host is a NetAsq");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");
 script_require_ports(1300);
 exit(0);
}

#
# The script code starts here
#

port=1300;

if (get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 req=string("NESSUS\r\n");
 send(socket:soc, data:req);
 r=recv(socket:soc,length:512);
 
 if (ereg(pattern:"^200 code=[0-9]+ msg=.*", string:r))
 {
 	req=string("QUIT\r\n");
 	send(socket:soc, data:req);
 	r=recv(socket:soc,length:512);
	if (ereg(pattern:"^103 code=[0-9]+ msg=.*", string:r))
	{
		security_note(port);
	}
 }
 close(soc);
}
exit(0);
