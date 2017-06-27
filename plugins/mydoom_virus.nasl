#
# (C) Tenable Network Security, Inc.
#

#
# rev 1.7: fixes a bug introduced in rev 1.6 spotted by Phil Bordelon 
# rev 1.6: MyDoom.B detection
#

include("compat.inc");

if(description)
{
 script_id(12029);
 script_version ("$Revision: 1.21 $");
 script_cvs_date("$Date: 2013/01/30 17:04:32 $");

 script_name(english:"MyDoom Virus Backdoor Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a suspicious application installed." );
 script_set_attribute(attribute:"description", value:
"The MyDoom backdoor is listening on this port. An attacker may connect to it
to retrieve sensitive information, e.g. passwords or credit card numbers." );
  # http://www.symantec.com/security_response/writeup.jsp?docid=2004-012612-5422-99
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9670fc4" );
  # http://www.symantec.com/security_response/writeup.jsp?docid=2004-022011-2447-99
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f14fece" );
  # http://web.archive.org/web/20040603115256/http://www.math.org.il/newworm-digest1.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00c06271" );
 script_set_attribute(attribute:"solution", value:
"Use an antivirus package to remove it." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/01/27");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();
 
 script_summary(english:"Detect MyDoom worm");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");
 script_dependencie("os_fingerprint.nasl");
 exit(0);
}

include('global_settings.inc');

os = get_kb_item("Host/OS");
if ( os && "Windows" >!< os ) exit(0);


ports = make_list();
if ( thorough_tests )
{
 for ( port = 3127 ; port < 3198 ; port ++ ) 
 {
	ports = make_list(ports, port);
 }
}


ports = make_list(ports, 1080,80,3128,8080,10080);

foreach port (ports)
{
 if ( get_port_state(port) ) 
 {
	req = string("a");
	soc = open_sock_tcp(port);
	if ( soc ) 
	{
	send(socket:soc, data:req);
	r = recv(socket:soc, length:10, timeout:3);
	close(soc);
	if ( r && (strlen(r) == 8) && (ord(r[0]) == 4) ) security_hole(port); 
	}
 }
}

