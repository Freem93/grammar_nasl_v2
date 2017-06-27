#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(10728);
 script_version ("$Revision: 1.20 $");
 script_cvs_date("$Date: 2011/08/16 21:07:11 $");

 script_name(english:"ISC BIND 9.x AUTHORS Map Remote Version Disclosure");
 script_summary(english:"Queries the CHAOS TXT record authors.bind");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote name server can be fingerprinted." );
 script_set_attribute(attribute:"description", value:
"It was possible to determine that the remote name server is running
BIND 9.x by querying it for the AUTHORS map." );
 script_set_attribute(attribute:"solution", value:
"Change the source code to prevent fingerprinting the server." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/08/23");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2011 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencies("bind_version.nasl");
 script_exclude_keys("bind/version");
 script_require_keys("DNS/udp/53");

 exit(0);
}

#
# The script code starts here
#
# We try to gather the version number via TCP first, and if this
# fails (or if the port is closed), we'll try via UDP
#

 soctcp53 = 0;
 
 if(get_port_state(53))
  {
  soctcp53 = open_sock_tcp(53);
 }
 if(!soctcp53){
  if(!(get_udp_port_state(53)))exit(0);
  socudp53 = open_sock_udp(53);
  soc = socudp53;
  offset = 0;
  }
  else {
  	soc = soctcp53;
	offset = 2;
  	}
  
 if (soc)
 {
  
  raw_data = raw_string(
			0x00, 0x0A, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x07);
  
  if(offset)raw_data = raw_string(0x00, 0x1E) + raw_data;
  
  raw_data = raw_data + "AUTHORS";
  raw_data = raw_data + raw_string( 0x04 );
  raw_data = raw_data + "BIND";
  raw_data = raw_data + raw_string(
				   0x00, 0x00, 0x10, 0x00, 0x03);

  send(socket:soc, data:raw_data);
  result = recv(socket:soc, length:1000);
  if("Bob Halley" >< result || "are better coders than I" >< result)
  {
   set_kb_item(name:"bind/version", value:"9");
   security_note(53);
  }
 close(soc);
 }
