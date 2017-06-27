#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11388);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2002-0872", "CVE-2002-0873");
 script_bugtraq_id(5451);
 script_osvdb_id(5061, 5062);
 script_xref(name:"DSA", value:"152");
 
 script_name(english:"l2tpd < 0.68 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a network tunneling application that is
affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of l2tpd prior to 0.67. 

This version is vulnerable to a buffer overflow that could allow an
attacker to gain a root shell on this host.

In addition, this program does not initialize its random number 
generator. Therefore, an attacker may predict some key values and 
hijack L2TP sessions established to this host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to l2tpd 0.68 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/04/09");
 script_cvs_date("$Date: 2013/01/05 02:31:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determines the version of the remote l2tpd");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");
 script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");
 script_dependencie("l2tp_detection.nasl");
 script_require_ports("Services/udp/l2tp");
 exit(0);
}

if ( ! get_kb_item("Services/udp/l2tp") ) exit(0);
port = 1701;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
		 
function find_firmware(rep)
{
 local_var firmware, i, len;
 
 for(i=12;i<strlen(rep);i++)
 { 
  len = ord(rep[i]) * 256 + ord(rep[i+1]);
  if(ord(rep[i]) & 0x80)len -= 0x80 * 256;
  if(ord(rep[i+5]) == 6)
  {
   firmware = ord(rep[i+6]) * 256 + ord(rep[i+7]);
   return firmware;
  }
  else i += len - 1;
 }
 return NULL;
}

req =  raw_string(0xC8, 2, 0, 20, 0, 0, 0, 0,0,0,0,0,0,8, 0,0,0,0,0,0);


soc = open_sock_udp(port);
send(socket:soc, data:req);
r = recv(socket:soc, length:1024);
if(!r)exit(0);
close(soc);
if(("l2tpd" >< r) || ("Adtran" >< r))
{
 firmware = find_firmware(rep:r);
 hi = firmware / 256;
 lo = firmware % 256;
 
 if((hi == 0x06)  && (lo <= 0x70))security_hole(port:port, proto:"udp");
}
