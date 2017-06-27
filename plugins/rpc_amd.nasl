# @DEPRECATED@
#
#
# Disabled on 2009-05-22
exit(0);

#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CVE. Changed description to match version

if(description)
{
 script_id(10211);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-1999-0704");
 script_bugtraq_id(614);
	 
 script_name(english:"amd Service Detection");
 
 desc["english"] = "
The amd RPC service is running. 
There is a bug in older versions of
this service less than am-utils-6.0.1 that allow an intruder to
execute arbitrary commands on your system.

Risk factor : High";

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



RPC_PROG = 300019;
tcp = 0;
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}

if(port)
{
 if(tcp)security_hole(port);
 else security_hole(port, protocol:"udp");
}
