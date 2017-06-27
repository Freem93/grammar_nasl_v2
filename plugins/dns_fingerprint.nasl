#
# (C) Tenable Network Security, Inc.
#

# This script is a very crude attempt at doing DNS fingerprinting
#

include("compat.inc");

if (description)
{
 script_id(11951);
 script_version("$Revision: 1.75 $");
 script_cvs_date("$Date: 2014/09/11 14:01:04 $");

 script_name(english:"DNS Server Fingerprinting");
 script_summary(english:"detects a name server type and version");

 script_set_attribute(attribute:"synopsis", value:"It may be possible to fingerprint the remote DNS server.");
 script_set_attribute(attribute:"description", value:
"This script attempts to identify the remote DNS server type and version
by sending various invalid requests to the remote DNS server and
analyzing the error codes returned.");
 script_set_attribute(attribute:"see_also", value:"http://cr.yp.to/surveys/dns1.html");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/12/16");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"DNS");

 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 script_dependencies("dns_server.nasl");
 script_require_keys("DNS/udp/53");

 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

id = rand() % 1024;
TIMEOUT = 5;

timeouts = 0;


if (report_paranoia < 2 && ! experimental_scripts)
 exit(0, "This DNS fingerprinting method is not reliable enough.");

global_var RD_BIT, TC_BIT, AA_BIT, Z0_BIT, RCODE15, Z1_BIT, Z2_BIT, OPCODE2, OPCODE3, OPCODE6, port;

port = 53;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");


function probe(message)
{
 local_var a, b, num_responses, r, rcode, report, sig, soc;

 soc = open_sock_udp(port);
 send(socket:soc, data:message);
 r = recv(socket:soc, length:4096);
 close(soc);
 if ( ! r )
 {
  timeouts ++;
  if ( timeouts > 3 && !thorough_tests)
  {
 	if ( report_verbosity < 2 ) exit(0);
	else {
	 report = '\nThe remote name server could not be fingerprinted (too many timeouts)\n';
	 security_note(port:port, proto:"udp", extra:report);
	 exit(0);
	}
   }
  return "t:";
 }


 rcode = substr(r, 3, 3);
 rcode = ord(rcode) & 0x0f;

 sig = string(rcode);
 if ( ord(r[2]) & TC_BIT ) sig += "TC";
 if ( ord(r[2]) & RD_BIT ) sig += "RD";
 if ( ord(r[2]) & AA_BIT ) sig += "AA";
 if ( ord(r[3]) & Z0_BIT ) sig += "Z0";
 if ( ord(r[3]) & Z1_BIT ) sig += "Z1";
 if ( ord(r[3]) & Z2_BIT ) sig += "Z2";

 if ( ord(r[5]) == 0 ) sig += "q";
 if ( ord(r[5]) > 1  ) sig += "Q2";

 if ( ord(r[5]) ) {
    a = substr(r, strlen(r) - 4, strlen(r) - 1);
    b = substr(message, strlen(message) - 4, strlen(message) - 1);
    if ( a != b ) sig += "X";
    }


 if ( ord(r[7]) != 0 ) sig += "D";

 sig += ":";
 return sig;
}

RD_BIT = 1;
TC_BIT = 2;
AA_BIT = 4;
Z0_BIT = 16;
RCODE15 = 15;
Z1_BIT = 32;
Z2_BIT = 64;
OPCODE2= 16;
OPCODE3= 24;
OPCODE6= 48;

i = 0;
nessus_example_com = raw_string(6) + "nessus" + raw_string(7) + "example" + raw_string(3) +"com";

test = probe(message:raw_string(0,0,0,0,0,1,0,0,0,0,0,0) + nessus_example_com + raw_string(0,0,16,0,1));
if ( "t:" >< test ) exit(0);

probes[i++] = raw_string(0,0,8,0,0,1,0,0,0,0,0,0) + nessus_example_com + raw_string(0,0,16,0,1);
probes[i++] = raw_string(0,0,0,0,0,1,0,0,0,0,0,0) + nessus_example_com + raw_string(0,0,16,0,3);
probes[i++] = raw_string(0,0,0,0,0,1,0,0,0,0,0,0) + nessus_example_com + raw_string(0,0,16,0,63);
probes[i++] = raw_string(0,0,0,0,0,2,0,0,0,0,0,0) + nessus_example_com + raw_string(0,0,16,0,1,0,0,16,0,1);
probes[i++] = raw_string(0,0,32,0,0,1,0,0,0,0,0,0) + nessus_example_com + raw_string(0,0,16,0,1);
probes[i++] = raw_string(0,0,40,0,0,1,0,0,0,0,0,0) + nessus_example_com + raw_string(0,0,16,0,1);
probes[i++] = raw_string(0,0,0,0,0,0,0,0,0,0,0,0);
probes[i++] = raw_string(0,0,0,0,0,1,0,0,0,0,0,0,6);
probes[i++] = raw_string(0,0,0,0,0,1,0,0,0,0,0,0) + nessus_example_com + raw_string(0);
probes[i++] = raw_string(0,0,TC_BIT,0,0,1,0,0,0,0,0,0) + nessus_example_com + raw_string(0,0,16,0,1);
probes[i++] = raw_string(0,0,0,0,0,1,0,0,0,0,0,0, 7) + "AUTHORS" + raw_string(4) +"BIND" + raw_string(0,0,16,0,3);
probes[i++] = raw_string(0,0,AA_BIT,0,0,1,0,0,0,0,0,0) + nessus_example_com + raw_string(0,0,16,0,1);
probes[i++] = raw_string(0,0,0,RCODE15,0,1,0,0,0,0,0,0) + nessus_example_com + raw_string(0,0,16,0,1);
probes[i++] = raw_string(0,0,0,Z0_BIT,0,1,0,0,0,0,0,0) + nessus_example_com + raw_string(0,0,16,0,1);
probes[i++] = raw_string(0,0,0,Z1_BIT,0,1,0,0,0,0,0,0) + nessus_example_com + raw_string(0,0,16,0,1);
probes[i++] = raw_string(0,0,0,Z2_BIT,0,1,0,0,0,0,0,0) + nessus_example_com + raw_string(0,0,16,0,1);
probes[i++] = raw_string(0,0,OPCODE2,0,0,1,0,0,0,0,0,0) + nessus_example_com + raw_string(0,0,16,0,1);
probes[i++] = raw_string(0,0,OPCODE3,0,0,1,0,0,0,0,0,0) + nessus_example_com + raw_string(0,0,16,0,1);
probes[i++] = raw_string(0,0,OPCODE6,0,0,1,0,0,0,0,0,0) + nessus_example_com + raw_string(0,0,16,0,1);
probes[i++] = raw_string(0,0,0,0,0,1,0,0,0,0,0,0) + nessus_example_com + raw_string(0,0,16,0,1);
probes[i++] = raw_string(0,0,0,0,0,1,0,0,0,0,0,0,21) + "erre-con-erre-cigarro" + raw_string(7) + "maradns" + raw_string(3) + "org" + raw_string(0,0,16,0,1);
probes[i++] = raw_string(0,0,0,0,0,1,0,0,0,0,0,0,7) + "version" + raw_string(6) + "server" + raw_string(0,0,16,0,3);
probes[i++] = raw_string(0,0,0,0,0,1,0,0,0,0,0,0,7) + "VERSION" + raw_string(4) + "BIND" +raw_string(0,0,16,0,3);


fingerprint = "";

for ( i = 0 ; probes[i] ; i ++ )
{
 fingerprint += probe(message:probes[i]);
}

if (COMMAND_LINE) display("Fingerprint= ",fingerprint, "\n");

db = "
Alcatel SpeedTouch DSL:4:2:2:4Q2:4:4:4q:1:1:4TC:2:4AA:4:4Z0:4Z1:4Z2:4:4:4:4:4:2:0XD:
AVM FRITZ!Box:4:2:5:t:4:4:1q:1:t:0X:2:0X:0X:0X:0X:0X:4:4:4:0X:0X:2:0XD:
Buffalo AirStation Router:4q:5q:5q:2:4q:4q:5q:1q:1q:5q:5q:0X:2:0X:0X:0X:4q:4q:4q:0X:0X:5q:5q:
CISCO Name Server:4q:3:3:1q:4q:4q:1q:1X:1X:3TC:3:3:3:3Z0:3Z1:3Z2:4q:4q:4q:3:3:3:3:
CISCO Network Registrar Name Server:1q:2:2:1q:5:1q:1q:1q:1q:0AAXD:2:0AAXD:0AAXD:0AAXD:0AAXD:0AAXD:4q:4q:4q:0AAXD:0AAXD:2:2:
CISCO Network Registrar Name Server:1q:2:2:1q:5:1q:1q:1q:1q:0X:2:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:2:2:
CISCO Network Registrar Name Server:1q:2:2:1q:5:1q:1q:1q:1q:0:2:0:0:0:0:0:4q:4q:4q:0:0:2:2:
Check Point DNS Server:4q:5:5q:1q:1:1q:1q:1q:1q:0X:5:0X:2:0X:0X:0X:4q:4q:4q:0X:0X:5:5q:
dnsmasq 1.13:5:5:5:5Q2:5:5:5q:t:t:5:5:5:5:5Z0:5Z1:5Z2:5:5:5:5:5:5:5:
dnsmasq 2.13:5:0AAXD:5:5Q2:5:5:5q:t:t:5:0AAXD:5:5:5Z0:5Z1:5Z2:5:5:5:5:5:0AAXD:0AAXD
dnsmasq 2.15:5:0AAXD:5:5Q2:5:5:5q:t:t:5:0AAXD:5:5:5Z0:5Z1:5Z2:5:5:5:5:5:0AAXD:0AAXD:
dnsmasq 2.20:5:0AAXD:5:5Q2:5:5:5q:t:t:5:0AAXD:5:5:5Z0:5Z1:5Z2:5:5:5:5:5:0AAXD:0AAXD:
dnsmasq 2.22:5:5:5:5Q2:5:5:5q:t:t:5:0AAXD:5:5:5Z0:5Z1:5Z2:5:5:5:5:5:5:0AAXD:
dnsmasq 2.27:1q:2:2:1q:1:1q:1q:1q:1q:0X:0AAXD:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:2:0AAXD:
dnsmasq 2.31:4q:5:5:1q:1:1q:1q:1q:1q:0X:0AAXD:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:2:0AAXD:
dnsmasq 2.32:1q:2:2:1q:2:1q:1q:1q:1q:0TC:0AAXD:0X:0X:0Z0X:0X:0Z2X:4q:4q:4q:0X:0X:2:0AAXD:
dnsmasq 2.33:4q:t:t:1q:1:1q:1q:1q:1q:0X:0AAXD:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:t:0AAXD:
Efficient Networks Routers Internal DNS Server:4q:2:2:1q:2:1q:1q:1q:1q:1q:2:0X:0X:0X:0Z0X:0X:0X:0X:0Z2X:4q:0X:4q:0X:
Fortress Linux DNS Server:4:1q:1q:1Q2:4:4:1q:1:1:1:0AAXD:1AAq:1q:1Z0q:1q:1Z2q:4:4:4:1q:1q:0XD:0AAXD:
ISC BIND 4.9:1q:2:2:1q:4q:4q:1q:1X:1:0TC:2:0X:0X:0Z0X:0Z1X:0Z2X:4q:4q:4q:0X:0X:2:0AAXD:
ISC BIND 4.9 + OpenBSD patches:1q:2:2:1q:4q:4q:1q:1q:1q:0TC:2:0X:0X:0Z0X:0Z1X:0Z2X:4q:4q:4q:0X:0X:2:2:
ISC BIND 8.1:1q:2:2:1q:2:1q:1q:1X:1:0TC:2:0X:0X:0Z0X:0Z1X:0Z2X:4q:4q:4q:0X:0X:2:0AAXD:
ISC BIND 8.1:1q:2:2:1q:2:1q:1q:1q:1q:0TC:2:3AAX:3AAX:3AAZ0X:3AAZ1X:3AAZ2X:4q:4q:4q:3AAX:3AAX:2:0AAXD:
# Below is actually Bind 8.1.2
ISC BINS 8.1:1q:2:2:1q:5:1q:1q:1X:1:0TC:2:0X:0X:0Z0X:0Z1X:0Z2X:4q:4q:4q:0X:0X:2:0AAXD:
# Bind 8.1.2 on Solaris
ISC BIND 8.1:1q:0:0:1q:5:1q:1q:1q:1q:0TC:0:0:0:0Z0:0Z1:0Z2:4q:4q:4q:0:0:0:0AAXD:
ISC BIND 8.2:4q:5:5:1q:5:1q:5q:1q:1q:0Z1X:5:0Z1X:15Z1X:0Z1X:0Z1X:0Z1X:4q:4q:4q:0Z1X:0Z1X:5:0AAZ1XD:
ISC BIND 8.2:4q:5:5:1q:2:1q:1q:1q:1q:0X:5:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:5:0AAXD:
# net-dns/bind-9.2.2-r3 on Gentoo 1.4
ISC BIND 9.2.2:4q:5:5:1q:2:1q:1q:1q:1q:0X:5:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:5:0AAXD:
# Below is actually BIND 8.2-6 (RedHat RPM)
ISC BIND 8.2:1q:2:2:1q:2:1q:1q:1X:1:0TC:2:0X:0X:0Z0X:0X:0Z2X:4q:4q:4q:0X:0X:2:0AAXD:
ISC BIND 8.3:1q:2:2:1q:2:1q:1q:1q:1q:0TC:2:0X:0X:0Z0X:0X:0Z2X:4q:4q:4q:0X:0X:2:0AAXD:
ISC BIND 8.3:1q:2:2:1q:2:1q:1q:1q:1q:0TC:5:0X:0X:0Z0X:0X:0Z2X:4q:4q:4q:0X:0X:2:5:
ISC BIND 8.3:1q:2:2:t:2:1q:1q:1q:1q:0TC:2:0X:0X:0Z0X:0X:0Z2X:4q:4q:4q:0X:0X:2:0AAXD:
ISC BIND 8.3:1q:2:2:1q:2:1q:1q:t:t:0TC:2:0X:0X:0Z0X:0X:0Z2X:4q:4q:4q:0X:0X:2:0AAXD:
# Below is actually Bind 8.3.6
ISC BIND 8.3:1q:5:5:1q:2:1q:1q:1q:1q:5TC:5:5:5:5Z0:5Z1:5Z2:4q:4q:4q:5:5:5:5:
ISC BIND 8.4:1q:2:2:1q:2:1q:1q:1q:1q:0TC:2:0X:0X:0Z0X:0X:0Z2X:4q:4q:4q:0X:0X:2:0AAXD:
ISC BIND 8.4:1q:2:2:1q:2:1q:t:1q:1q:0TC:2:0X:0X:0Z0X:0X:0Z2X:4q:4q:4q:0X:0X:2:0AAXD:
ISC BIND 8.4:1q:2:2:1q:2:1q:t:t:t:0TC:2:0X:0X:0Z0X:0X:0Z2X:4q:4q:4q:0X:0X:2:0AAXD:
# BIND 9.1.3 actually
ISC BIND 9.1:4q:5:5:1q:5:1q:1q:1q:1q:0X:0AAXD:0X:15X:0X:0X:0X:4q:4q:4q:0X:0X:5:0AAXD:
ISC BIND 9.2.1:4q:5:5:1q:2:1q:1q:1q:1q:0X:0X:0AAXD:0X:0X:0X:0X:4q:4q:4q:0X:0X:5:0AAXD:
ISC BIND 9.2.1:4q:5:5:1q:2:1q:1q:1q:1q:0X:0AAXD:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:5:0AAXD:
ISC BIND 9.2.1:4q:5:5:1q:2:1q:1q:t:t:0X:5:0X:0X:0X:0X:0X:4q:4q:t:0X:0X:5:0AAXD:
ISC BIND 9.2.1:4q:5:5:1q:2:1q:1q:1q:1q:0X:0AAXD:0X:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:5:
ISC BIND 9.2.1:4q:5:5:1q:2:1q:1q:1q:1q:5:5:5:5:5:5:5:4q:4q:4q:5:5:5:5
ISC BIND 9.2.2rc1:4q:5:5:1q:2:1q:1q:1q:1q:5:0AAXD:5:5:5:5:5:4q:4q:4q:5:5:5:0AAXD:
ISC BIND 9.2.2:4q:5:5:1q:2:1q:1q:1q:1q:5:5:5:5:5:5:5:4q:4q:4q:5:5:5:5:
ISC BIND 9.2.2:4q:4q:5:1q:1q:2:1q:1q:t:0X:0AAXD:0X:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:5:
ISC BIND 9.2.2:4q:5:5:1q:5:5q:1q:1q:1q:5:0AAXD:5:5:5:5:5:4q:4q:4q:5:5:5:0AAXD:
ISC BIND 9.2.2:4q:5:5:1q:2:1q:1q:1q:1q:0X:0AAXD:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:5:0AAXD:
ISC BIND 9.2.3:4q:5:5:1q:1:1q:1q:1q:1q:0X:0AAXD:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:5:0AAXD:
ISC BIND 9.2.3:4q:5:5:1q:1:1q:1q:1q:1q:0X:t:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:5:t:
ISC BIND 9.2.3:4q:5:5:1q:1:1q:t:1q:1q:0X:0AAXD:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:5:0AAXD:
ISC BIND 9.2.3:4q:2:5:1q:1:1q:1q:1q:1q:0X:0AAXD:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:2:0AAXD:
ISC BIND 9.2.3:4q:5:5:1q:1:1q:1q:1q:1q:0X:5:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:5:0AAXD:
ISC BIND 9.2.3:4q:5:5:1q:1:1q:1q:1q:1q:0X:5:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:5:5:
ISC BIND 9.2.3:4q:2:5:1q:1:1q:1q:1q:1q:0X:3AAX:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:2:3AAX:
ISC BIND 9.2.3:0X:4q:4q:5X:5X:5X:5X:1q:1X:1:1q:1q:0X:0X:0AAXD:0AAXD:0X:0X:0X:0X:0X:4q:4q:
ISC BIND 9.2.3:4q:5:5:1q:1:1q:t:1q:0X:5:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:5:0AAXD:
ISC BIND 9.2.3:4q:5:5:1q:1:1q:t:1q:1q:0X:5:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:5:0AAXD
ISC BIND 9.2.3:4q:5:5:1q:1:1q:t:t:t:0X:0AAXD:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:5:0AAXD:
ISC BIND 9.2.4:4q:5:5:1q:1:1q:1q:1q:1q:5:5:5:5:5:5:5:4q:4q:4q:5:5:5:5:
ISC BIND 9.2.4:4q:5:5:1q:1:1q:t:t:1q:0X:0AAXD:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:5:0AAXD:
ISC BIND 9.3.0:4q:5:5:1q:1:1q:1q:1q:1q:5:5:5:5:5:5:5:4q:4q:4q:5:5:5:5:
# bind-9.3.0-0.beta2.1mdk
ISC BIND 9.3.0:4q:2:5:1q:1:1q:t:1q:1q:0X:0AAXD:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:2:0AAXD:
ISC BIND 9.3.0:4q:2:5:1q:1:1q:1q:1q:1q:0X:0AAX:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:2:0AAXD:
ISC BIND 9.3.0:4q:2:5:1q:1:1q:t:1q:1q:0X:0AAX:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:2:0AAXD:
ISC BIND 9.3.1:4q:5:5:1q:1:1q:t:1q:1q:5:5:5:5:5:5:5:4q:4q:4q:5:5:5:5:
ISC BIND 9.3.1:4q:2:5:1q:1:1q:1q:t:t:0X:0AAX:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:2:0AAXD:
ISC BIND 9.3.1:4q:2:5:1q:1:1q:1q:1q:1q:0X:0AAX:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:2:0AAX:
ISC BIND 9.4-ESV-R5-P1:4q:5:5:1q:1:1q:1q:1q:1q:0X:0AAX:0X:0X:0Z0X:0X:0X:4q:4q:4q:0X:0X:5:0AAXD:
ISC BIND 9.4.1:4q:5:5:1q:1:1q:1q:1q:1q:5:0AAX:5:5:5Z0:5:5:4q:4q:4q:5:5:5:0AAXD:
ISC BIND 9.4.2:4q:2:5:1q:1:1q:1q:1q:1q:0X:0AAX:0X:0X:0Z0X:0X:0X:4q:4q:4q:0X:0X:2:0AAXD:
ISC BIND 9.4.2-P2-W2:4q:5:5:1q:1:1q:1q:t:t:5:0AAXD:5:5:5Z0:5:5:4q:4q:4q:5:5:5:0AAXD:
ISC BIND 9.5.0:4q:5:5:1q:1:1q:1q:1q:1q:5:0AAXD:5:5:5Z0:5:5:4q:4q:4q:5:5:5:0AAXD:
ISC BIND 9.6.-ESV-R3:4q:5:5:1q:1:1q:1q:1q:1q:3AAX:0AAXD:3AAX:3AAX:3AAZ0X:3AAX:3AAX:4q:4q:4q:3AAX:5:5:0AAXD:
ISC BIND 9.6.2-P3:4q:5:5:1q:1:1q:1q:1q:1q:5:5:5:5:5Z0:5:5:4q:4q:4q:5:5:5:5:
# Debian 9.7.3.dfsg-1~squeeze3
ISC BIND 9.7.3-P3:4q:5:5:1q:1:1:t:t:1q:5:0AAXD:5:5:5Z0:5:5:4q:4q:4q:5:5:5:0AAXD:
# Debian 9.7.3.dfsg-1~squeeze8
ISC BIND 9.7.6-P4:4q:5:5:1q:1:1:1q:1q:1q:5:0AAX:5:5:5Z0:5:5:4q:4q:4q:5:5:5:0AAX:
# CentOS 6.3 bind-9.8.2-0.10.rc1.el6_3.5.x86_64
ISC BIND 9.8.2:4q:5:5:1q:1:1:1q:1q:1q:5:0AAXD:5:5:5Z0:5:5:4q:4q:4q:5:5:5:0AAXD:
# FreeBSD 9.1-RELEASE-p6 OS
ISC BIND 9.8.3-P4:4q:5:5:1q:1:1:1q:1q:1q:3AAX:0AAXD:3AAX:3AAX:3AAZ0X:3AAX:3AAX:4q:4q:4q:3AAX:5:5:0AAXD:
# BIND 9.0.2-P2, compiled from source.
ISC BIND 9.9.2-P2:4q:5:5:1q:1:1:1q:1q:1q:5:5:5:5:5Z0:5:5:4q:4q:4q:5:5:5:5:
ISC BIND 9.9.3-P2:4q:5:5:1q:1:1:1q:1q:1q:0X:0AAXD:0X:0X:0Z0X:0X:0X:4q:4q:4q:0X:0X:5:0AAXD:
Linksys Router Name Server:0:0:0:0Q2:0:0:0q:0:0:0:0:0:0:0Z0:0Z1:0Z2:0:0:0:0:0:0:0:
# Indeed MaraDNS 1.0.20
MaraDNS 1.0:4q:5q:5q:t:4q:4q:4q:t:t:5q:5q:5q:5q:5q:5q:5q:4q:4q:4q:5q:2q:5q:5q:
MaraDNS 1.3:4q:0:5q:1q:3q:4q:1q:1q:1q:1q:0:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:0XD:0XD
# MaraDNS straight out of Debian stable (v1.4.12-5)
MaraDNS 1.4.12:4:3AAX:3AAX:t:4:4:t:t:t:3AAX:5q:3AAX:3AAX:3AAX:3AAX:3AAX:4:4:4:3AAX:5q:5q:5q:
# MaraDNS 0.9.15-1
MaraDNS 0.9:4q:5q:5q:4q:4q:4q:4q:t:t:5q:5q:5q:5q:5q:5q:5q:4q:4q:4q:5q:2q:5q:5q:
Microsoft Windows NT 4 Name Server:1:4:4:1Q2:t:4:4X:1q:0X:4X:0TCX:4X:0X:15X:0Z0X:0X:4:4:4:0X:0X:4:4:
Microsoft Windows NT 4 Name Server:1:4:4:1Q2:t:4:1q:2:2:2TC:4:2:2:2Z0:2:2:4:4:4:2:2:4:4:
Microsoft Windows 2000 Name Server:1:4:4:1Q2:t:4:1q:0X:0X:0TCX:4:0X:15X:0Z0X:0X:0X:4:4:4:0X:0X:4:4:
Microsoft Windows 2000 Name Server:1q:2:2:1q:2:1q:1q:1q:1q:0TC:5:0X:0X:0Z0X:0X:0Z2X:4q:4q:4q:0X:0X:2:5
Microsoft Windows 2000 Name Server:t:t:t:t:t:t:1q:t:0X:0X:t:0X:15X:0Z0X:0X:0X:t:t:t:0X:0X:t:4:
Microsoft Windows 2003 Name Server:4:4:4:1Q2:t:1:1q:1:0X:0X:4:0X:15X:0X:0X:0X:4:4:4:0X:2:4:4:
Microsoft Windows 2003 Name Server:4:4:4:1Q2:t:1:1:q:1:2:2:4:2:2:2:2:2:4:4:4:2:2:4:4:
Microsoft Windows 2003 Name Server:4:4:4:1Q2:t:1:1q:1:0X:0X:4:0X:15X:0X:0X:0X:4:4:4:0X:0X:4:4:
Microsoft Windows 2003 Name Server:4:4:4:1Q2:t:1:1q:1:4:0X:4:0X:15X:0X:0X:0X:4:4:4:0X:0X:4:4:
Microsoft Windows 2003 Name Server:4:4:4:1Q2:t:1:1q:1:4:2:4:2:2:2:2:2:4:4:4:2:2:4:4:
Microsoft Windows 2003 Name Server:4:4:4:1Q2:t:1:1q:t:t:0X:4:0X:15X:0X:0X:0X:4:4:4:0X:2:4:4
Microsoft Windows 2003 Name Server:4:4:4:1Q2:t:1:1q:1:2:2:4:2:2:2:2:2:4:4:4:2:2:4:4:
Microsoft Windows 2003 Name Server:4:4:4:1Q2:t:1:1q:1:4:3AAX:4:3AAX:3AAX:3AAX:3AAX:3AAX:4:4:4:3AAX:3AAX:4:4:
Microsoft Windows 2003 Name Server:4:4:4:1Q2:t:1:t:1:4:0X:4:0X:15X:0X:0X:0X:4:4:4:0X:2:4:4:
Microsoft Windows 2003 Name Server:4:4:4:1Q2:t:1:1q:1:0:0X:4:0X:15X:0X:0X:0X:4:4:4:0X:0X:4:4:
Microsoft Windows 2008 R2 Name Server:t:t:t:t:t:t:t:t:0X:0X:t:0X:15X:0X:0X:0X:t:t:4:0X:0X:0AAXD:t:
# Windows 2003 3790 Service Pack 2?
# Microsoft Windows 2003 Name Server:4:t:t:t:t:t:t:1:2:2:t:2:2:2:2:2:t:t:t:2:2:t:t:
NetWare 5.1 Name Server:5X:2:2:1q:4q:4q:1q:1X:1:0TCX:2:0X:0X:0Z0X:0Z1X:0Z2X:4q:4q:4q:0X:0X:2:2:
NetWare 6 Name Server:4q:5:5:1q:2:1q:1q:1q:1q:0X:5:0X:0X:0X:0X:0X:4q:4q:4q:0X:0X:5:5:

mydns v0.10.0:4q:4q:4q:1q:4q:4q:1q:1q:1q:1TCq:4q:5:5:5:5:5:4q:4q:4q:5:5:4q:4q:
mydns v0.10.1:4q:4q:4q:1q:4q:4q:1q:1q:1q:1TCq:4q:5AA:5:5:5Z1:5Z2:4q:4q:4q:5:5:4q:4q:
NLnet Labs NSD:4q:0:5q:1q:4q:4q:1q:1q:1q:1q:0:2:2:2:2:2:4q:4q:4q:2:2:0XD:0XD:
NLnet Labs NSD:4q:0:5q:1q:3q:4q:1q:1q:1q:1q:0:3AAX:3AAX:3AAX:3AAX:3AAX:4q:4q:4q:3AAX:2:0XD:0XD:
NLnet Labs NSD:4q:0:5q:1q:3q:4q:1q:1q:1q:1q:0:2:2:2:2:2:4q:4q:4q:2:2:0XD:0XD:
Nominum ANS 2.6.0.0-5:4q:5:5:1q:5:1:1q:1q:1q:5:5:5:5:5:5:5:4q:4q:4q:5:5:0AAXD:0AAXD:
PowerDNS 2.9.13:2:2X:2X:2:2:2:t:t:t:2:0AA:2:2:2:2:2:2:2:2:2:2:0AA:0AA:
PowerDNS 2.9.15:3AAX:3AAX:3AAX:3AAX:3AAX:3AAX:t:t:t:3AAX:0AA:3AAX:3AAX:3AAX:3AAX:3AAX:3AAX:3AAX:3AAX:3AAX:2:0AA:0AA:
PowerDNS 2.9.21.1:t:2X:2X:2:4AA:t:t:t:t:2:0AAX:2:2:2:2:2:t:t:t:2:2:0AAX:0AAX:
# pdnsd 1.1.7 -  http://home.t-online.de/home/Moestl/
pdnsd:4q:4:4:3Q2:4q:4q:1q:1q:1q:3:4:3:t:1q:3:1q:4q:4q:4q:3:0:4:4:
pdnsd:4q:4:4:3Q2:4q:4q:1q:1q:1q:3:4:3:t:1q:3:1q:4q:4q:4q:3:0XD:4:4:
pdnsd:4q:4:4:2Q2:4q:4q:1q:1q:1q:2:4:2:t:1q:2:1q:4q:4q:4q:2:2:4:4:
pdnsd:4q:4:4:3Q2X:4q:4q:1q:1q:1q:3X:4:3X:t:1q:3X:1q:4q:4q:4q:3X:0X:4:4:
pdnsd:4q:4:4:3Q2X:4q:4q:t:1q:1q:3X:4:t:t:1q:3X:1q:4q:4q:4q:3X:0X:4:4:
# pdnsd 1.2.5
pdnsd:4q:4:4:3Q2X:4q:4q:1q:1q:1q:3X:4:3X:t:1q:3X:1q:4q:4q:4q:3X:0XD:4:4:
Simple DNS Plus 5.2 (Build 117):4:4:4:5:4:1q:1q:1:1:5:4:5:5:5:5:5:4:4:4:5:5:4:4:
SMC Layer 3 Switch:1q:3RDAAX:3RDAAX:4q:4q:4q:1q:1q:3RDAAX:3RDAAX:3RDAAX:3RDAAX:1q:1q:1q:1q:4q:4q:4q:3RDAAX:0RDXD:3RDAAX:3RDAAX:
Speedstream DSL Router:0X:5q:4q:2:5q:2:5q:4q:1q:5q:5q:5q:2:0X:0X:0X:0X:4q:4q:0X:0X:5q:0X:
SpeedTouch DSL Router:0:5:5:0Q2:0:0:0q:0:0:0TC:5:0AA:4:0Z0:0Z1:0Z2:0:0:0:0:0:5:0AAXD:
Symantec Enterprise Firewall 6:4:5:5:t:4:4:1q:1:t:5TC:5:5AA:5:5Z0:5Z1:5Z2:4:4:4:5:5:5:5:
Symantec Enterprise Firewall 7:4:5:5:t:4:4:1q:1:t:3RD:5:3RD:3RD:3RD:3RD:3RD:4:4:4:3RD:0AA:5:5:
Symantec Enterprise Firewall:4q:5q:5q:2:4q:4q:5q:1q:1q:5q:5q:0X:2:0X:0X:0X:4q:4q:4q:0X:0X:5q:5q:


";

m = egrep(pattern:fingerprint, string:db);
if ( m )
{
 m = split(m);
 dns = NULL;
 num = 0;
 foreach line (m)
 {
 n = split(line, sep:":", keep:FALSE);
 dns += n[0] + '\n';
 num ++;
 }

 if ( num == 1 )
   report = string(
     "\n",
     "The remote name server could be fingerprinted as being :\n\n",
     "  ", dns, "\n"
   );
 else
   report = string(
     "\n",
     "The remote name server could be fingerprinted as being one of the\n",
     "following :\n\n",
     "  ", dns, "\n"
   );
 security_note(port:port, proto:"udp", extra:report);
 exit(0);
}


results = split(fingerprint, sep:":", keep:0);
db = egrep(pattern:"^[^#].*", string:db);
foreach sig (split(db))
  {
   sig = sig - '\n';
   if ( strlen(sig) > 1 )
   {
    v = split ( sig, sep:":", keep:0);
    n = max_index(v);
    dns = v[0];
    diff = 0;
    for ( i = 1 ; i < n ; i ++ )
	if ( v[i] != results[i - 1] ) diff ++;

    differences[dns] = diff;
   }
  }

m = 99999;
foreach d (differences) if (d < m) m = d;

if ( m < 10 )
 {
    dns = NULL;
    foreach i (keys(differences))
    {
     if ( differences[i] == m )
     {
      if ( ! dns ) dns = i;
      else dns += '\n' + i;
     }
    }
   report = string(
     "\n",
     "Nessus was not able to reliably identify the remote DNS server type.\n",
     "It might be :\n\n",
     "  ", dns, "\n\n",
     "The fingerprint differs from these known signatures on ", m, " points.\n",
     "If you know the type and version of the remote DNS server, please send\n",
     "the following signature to dns-signatures@nessus.org :\n\n",
     "  ", fingerprint, "\n"
   );
  security_note(port:port, proto:"udp", extra:report);
  exit(0);
}

 report = string(
   "\n",
   "It was not possible to fingerprint the remote DNS server.\n\n",
   "If you know the type and version of the remote DNS server, please send\n",
   "the following signature to dns-signatures@nessus.org :\n\n",
   "  ", fingerprint, "\n"
 );
 security_note(port:port, proto:"udp", extra:report);

