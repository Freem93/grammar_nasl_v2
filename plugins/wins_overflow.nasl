#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15912);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2013/02/14 16:25:03 $");

 script_cve_id("CVE-2003-0825");
 script_bugtraq_id(9624);
 script_osvdb_id(3903);
 script_xref(name:"MSFT", value:"MS04-006");

 script_name(english:"MS04-006: WINS Server Remote Overflow (830352) (uncredentialed check)");
 script_summary(english:"Determines if hotfix 830352 has been installed (Netbios)");
 
 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote Windows Internet Naming Service (WINS) is affected by a
vulnerability that could allow an attacker to execute arbitrary code on
this host. 

To exploit this flaw, an attacker would need to send a specially crafted
packet with improperly advertised lengths.");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://technet.microsoft.com/en-us/security/bulletin/ms04-006");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/06");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("netbios_name_get.nasl");
 script_exclude_keys("SMB/not_windows");
 script_require_ports(137);
 exit(0);
}

include("audit.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

port = 137;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");


request = raw_string (0x83, 0x98, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		      0x3E, 0x46, 0x45, 0x45, 0x46, 0x45, 0x4f, 0x45, 0x42, 0x45, 0x43, 0x45,
                      0x4d, 0x45, 0x46 ) + crap (data:"A", length:48) +
		      crap (data:raw_string(0x3F), length:192) + 
		      raw_string (0x22) + crap (data:raw_string (0x3F), length:34) + 
                      raw_string ( 0x00, 0x00, 0x20, 0x00, 0x01); 

send(socket:soc, data:request);

r = recv(socket:soc, length:4096);
if (!r) audit(AUDIT_RESP_NOT, port);

r = substr (r, 13, 17);

if ("FEEFE" >< r) security_hole(port:port, protocol:"udp");
else audit(AUDIT_HOST_NOT, "affected");
