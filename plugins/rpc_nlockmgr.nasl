# @DEPRECATED@
#
# Disabled on 2009-05-22
exit(0);

#
# (C) Tenable Network Security, Inc.
#


if(description)
{
 script_id(10220);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2000-0508");
 script_bugtraq_id(1372);
 script_xref(name:"OSVDB", value:"7306");

 script_name(english:"nlockmgr service");
 
 desc["english"] = "
The nlockmgr RPC service is running. 

If you do not use this service, then disable it as it may become a security
threat in the future, if a vulnerability is discovered.

Risk factor : Low";

 script_description(english:desc["english"]);
 
 script_summary(english:"checks the presence of a RPC service");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"RPC");
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");
include('global_settings.inc');

if ( report_paranoia < 2 ) exit(0);




RPC_PROG = 100021;
tcp = 0;
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}

if(port)
{
 if(tcp)security_warning(port);
 else security_warning(port, protocol:"udp");
}
