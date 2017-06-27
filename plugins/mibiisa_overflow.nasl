#
# (C) Tenable Network Security, Inc.
#

#
# XXXXXX This script should be rewritten to actually check for the overflow.
#

include("compat.inc");

if (description)
{
 script_id(11335);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");

 script_cve_id("CVE-2002-0797");
 script_bugtraq_id(4933);
 script_osvdb_id(8706);

 script_name(english:"Solaris mibiisa MIB Parsing Remote Overflow");
 script_summary(english:"Checks for the presence of mibiisa");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a program that may be prone to a buffer
overflow attack.");
 script_set_attribute(attribute:"description", value:
"The remote host is running mibiisa.

There is a buffer overflow in older versions of this software, which
may allow an attacker to gain a root shell on this host.

Note that Nessus did not actually check for this vulnerability so this
might be a false positive.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Jun/17");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?04427d11");
 script_set_attribute(attribute:"solution", value:"Apply the appropriate patch referenced in Sun's advisory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/06/04");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/09");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"SNMP");

 script_dependencie("snmp_settings.nasl", "os_fingerprint.nasl");
 script_require_keys("Settings/ParanoidReport");

 exit(0);
}


include("audit.inc");
include('global_settings.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

os = get_kb_item("Host/OS");
if( os )
{
 if("Solaris 9" >< os)exit(0);
}


#--------------------------------------------------------------------#
# Forges an SNMP GET NEXT packet                                     #
#--------------------------------------------------------------------#
function get_next(community, id, object)
{
 local_var len, tot_len, _r, o_len, a_len;
 len = strlen(community);
#display("len : ", len, "\n");
 len = len % 256;

 tot_len = 4 + strlen(community) + 12 + strlen(object) + 4;
# display(hex(tot_len), "\n");
 _r = raw_string(0x30, tot_len, 0x02, 0x01, 0x00, 0x04, len);
 o_len = strlen(object) + 2;

 a_len = 13 + strlen(object);
 _r = _r + community + raw_string( 0xA1,
	a_len, 0x02, 0x01, id,   0x02, 0x01, 0x00, 0x02,
	0x01, 0x00, 0x30,o_len) + object + raw_string(0x05, 0x00);
# display("len : ", strlen(_r), "\n");
 return(_r);
}



community = get_kb_item("SNMP/community");
if(!community)community = "public";


port = 32789;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);

first = raw_string(0x30, 0x82, 0x00,
		   0x0B, 0x06, 0x07, 0x2b, 0x06, 0x01, 0x02, 0x01,
		   0x01, 0x01);

id = 2;
req = get_next(id:id, community:community, object:first);

send(socket:soc, data:req);
r = recv(socket:soc, length:1025);
if(strlen(r) > 0)security_hole(port:port, proto:"udp");
