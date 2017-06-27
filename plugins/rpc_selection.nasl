# @DEPRECATED@
#
# Disabled on 2009-05-22
exit(0);

#
# (C) Tenable Network Security, Inc.
#

if(description)
{
 script_id(10231);
 script_version ("$Revision: 1.17 $");
 
 script_name(english:"selection service");
 
 desc["english"] = "
The selection RPC service is running. 
This service has a security hole that could
allow an attacker to remotely sniff the data
selected from within a SunView session.

*** No security hole regarding this program has been tested,
*** so this might be a false positive.

Solution : We suggest that you disable this service.

Risk factor : High";

 script_description(english:desc["english"]);
 
 script_summary(english:"Checks the presence of a RPC service");
 
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




RPC_PROG = 100015;
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
