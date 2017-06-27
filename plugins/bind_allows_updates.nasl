#
# (C) Tenable Network Security, Inc.
#

# This checks for a common misconfiguration issue, therefore no CVE/BID
# 

include("compat.inc");

if(description)
{
 script_id(11320);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2013/01/25 01:19:07 $");
 
 script_name(english:"ISC BIND Dynamic Updates Unauthorized Resource Record Manipulation");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote name server is misconfigured." );
 script_set_attribute(attribute:"description", value:
"The remote nameserver has dynamic updates enabled.

The dynamic updates let the BIND administrator update the name
service information dynamically.

However, it is possible to trick BIND into changing the resource
record for the zone it serves. An attacker may use this
flaw to hijack the traffic going to the servers and redirect
it to an arbitrary site." );
 script_set_attribute(attribute:"solution", value:
"If BIND is being used, add the option

      allow-update {none;};
      
in the named.conf configuration file to disable this 
feature entirely." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/04");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
 script_end_attributes();
 
 script_summary(english:"Determines if the UPDATE operation is implemented on the remote host");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_require_keys("DNS/udp/53");
 script_dependencies("dns_server.nasl");


 exit(0);
}


if(!get_udp_port_state(53))exit(0);

port = 53;

req = raw_string(

	  0xAB, 0xCD, 0x29, 0x00, 0x00, 0x01,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06) + "tested" + 
	 raw_string(0x02) + "by" + raw_string(0x06) + "nessus" +
	 raw_string(0x03) + "org" + 
	 raw_string(0x00, 0x00, 0x06, 0x00, 0x01, 
	 	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
   
soc = open_sock_udp(port);
if(soc)
{
 send(socket:soc, data:req);
 r = recv(socket:soc, length:1024);
 if(r)
 {
 if(!(ord(r[2]) & 0x09) &&
    !(ord(r[3]) & 0x04))
  {
   security_warning(port: port, protocol: "udp");
  } 
 }
 exit(0);
}
