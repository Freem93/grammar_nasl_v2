#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(25420);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2007-2279");
 script_bugtraq_id(24194);
 script_osvdb_id(36104);

 script_name(english:"Symantec Veritas Storage Foundation Scheduler Service (VxSchedService.exe) Remote Code Execution");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Symantec Storage Foundation for
Windows that is vulnerable to a remote scheduler service access.  An 
attacker may exploit this flaw to modify or create scheduled commands
and gain a full access to the system. 

To exploit this flaw, an attacker would need to send requests to the
TCP service listening on port 4888." );
 script_set_attribute(attribute:"solution", value:
"http://www.symantec.com/avcenter/security/Content/2007.06.01.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/04");
 script_cvs_date("$Date: 2012/08/23 21:13:31 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/06/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:veritas_storage_foundation");
 script_end_attributes();

 script_summary(english:"Test the VERITAS Storage Foundation Scheduler Service Access");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 
 script_require_ports(4888);
 exit(0);
}



include ("byte_func.inc");

port = 4888;

if (!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

req = 
	'<?xml version="1.0"?>\r\n' +
	'<Schedule>\r\n' +
	'<AppName>toto</AppName>\r\n' +
	'<ObjID>{c15f4527-3d6c-167b-f9c2-ca3908613b5a}</ObjID>\r\n' +
	'<TaskOpcode>0</TaskOpcode>\r\n' +
	'<Wrapper></Wrapper>\r\n' +
	'<XMLFilePath></XMLFilePath>\r\n' +
	'<Parameters></Parameters>\r\n' +
	'<PreScript></PreScript>\r\n' +
	'<PostScript></PostScript>\r\n' +
	'<UseGuid>0</UseGuid>\r\n' +
	'</Schedule>\r\n';

len = strlen(req);

data = 
	mkdword(len) +
	mkdword(2) +  # code(delete)
	mkdword(0x41414141) +
        "{c15f4527-3d6c-167b-f9c2-ca3908613b5a}" +
	mkbyte(0) +
	req;


send(socket:soc, data:data);
buf = recv(socket:soc, length:4096);


if ("{C15F4527-3D6C-167B-F9C2-CA3908613B5A}" >< buf && "-2147220979" >< buf)
  security_hole(port);
