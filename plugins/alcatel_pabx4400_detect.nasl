#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
   script_id(11019);
   script_version ("$Revision: 1.10 $");
   script_cvs_date("$Date: 2011/03/11 21:18:07 $");
   script_name(english:"Alcatel PABX 4400 Detection");
   script_summary(english:"Detects if the remote host is an Alcatel 4400");
   
 script_set_attribute(attribute:"synopsis", value:
"The remote host is an Alcatel phone system." );
 script_set_attribute(attribute:"description", value:
"The remote host is an Alcatel PABX 4400.

This device can be configured thru the serial
port or using this port. 

Outsiders should not be able to connect to this device." );
 script_set_attribute(attribute:"see_also", value:"http://www.alcatel-lucent.com" );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this host." );
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/08");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
   script_category(ACT_GATHER_INFO);
   
   script_copyright(english:"This script is Copyright (C) 2002-2011 Tenable Network Security, Inc.");
   script_family(english:"Service detection");
   script_require_ports(2533);
 
   exit(0);
}


#
# The code starts here
# 

port = 2533;
req = raw_string(0x00, 0x01, 0x43);
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 r = recv(socket:soc, length:2);
 close(soc);
 if ( strlen(r) < 2 ) exit(0);
 r_lo = ord(r[0]);
 r_hi = ord(r[1]);
 if((r_lo == 0) && (r_hi == 1))security_note(port);
}
