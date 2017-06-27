# @DEPRECATED@
#
# Disabled on 2009-05-22
exit(0);

#
# (C) Tenable Network Security, Inc.
#

if(description)
{
 script_id(10209);
 script_version ("$Revision: 1.15 $");

 script_name(english:"X25 service");
 
 desc["english"] = "
The X25 RPC service is running.  This service may allow an intruder
to connect via an X25 gateway rather than by TCP/IP. In addition to that,
it may become a security threat if a security vulnerability is
found.

If you do not use this service, then disable it. 

Risk factor : Low / Medium";

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


RPC_PROG = 100022;
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
