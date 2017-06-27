#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10239);
 script_version("$Revision: 1.37 $");
 script_cvs_date("$Date: 2014/02/19 01:34:32 $");

 script_cve_id("CVE-1999-0003","CVE-1999-0693");
 script_bugtraq_id(122, 641);
 script_osvdb_id(1073, 4505);
 script_xref(name:"CERT-CC", value:"CA-98.11");

 script_name(english:"CDE RPC tooltalk Service Multiple Overflows");
 script_summary(english:"Checks the presence of a RPC service");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code might be run on the remote host.");
 script_set_attribute(attribute:"description", value:
"The tooltalk RPC service is running.

A possible implementation fault in the ToolTalk object database server
may allow an attacker to execute arbitrary commands as root.

*** This warning may be a false positive since the presence of this
*** vulnerability is only accurately identified with local access.");
 script_set_attribute(attribute:"solution", value:
"Disable this service.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1998/09/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/22");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english:"RPC");
 if ( ! defined_func("bn_random") )
 	script_dependencie("rpc_portmap.nasl", "os_fingerprint.nasl");
 else
 	script_dependencie("rpc_portmap.nasl", "os_fingerprint.nasl", "solaris26_105802.nasl", "solaris26_x86_105803.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");
include("global_settings.inc");
include("sunrpc_func.inc");

if ( get_kb_item("BID-122") ) exit(0);
version = get_kb_item("Host/Solaris/Version");
if ( version && ereg(pattern:"5\.[0-6][^0-9]", string:version) ) exit(0);
else {
	version = get_kb_item("Host/OS");
	if ( version && ereg(pattern:"Solaris ([7-9]|1[0-9])", string:version) ) exit(0);
}


RPC_PROG = 100083;
tcp = 0;
port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}



if(port)
{
 vulnerable = 0;
 os = get_kb_item("Host/OS");
 if(!os )
	if ( report_paranoia < 2 )
		vulnerable = 0;
	else
		vulnerable = 1;
 else
 {
   if(ereg(pattern:"Solaris|HP-UX|IRIX|AIX", string:os))
   {
   if(ereg(pattern:"Solaris 2\.[0-6]", string:os))vulnerable = 1;
   if(ereg(pattern:"HP-UX.*(10\.[1-3]0|11\.0)", string:os))vulnerable = 1;
   if(ereg(pattern:"AIX 4\.[1-3]", string:os))vulnerable = 1;
   if(ereg(pattern:"IRIX (5\..*|6\.[0-4])", string:os))vulnerable = 1;
   }
   else if ( report_paranoia > 1 ) vulnerable = 1; # We don't know
 }

 if(vulnerable)
 {
 if(tcp)security_hole(port);
 else security_hole(port:port, protocol:"udp");
 }
}
