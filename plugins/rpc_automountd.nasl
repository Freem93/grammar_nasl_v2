# @DEPRECATED@
#
# Disabled on 2009-05-22
exit(0);

#
# (C) Tenable Network Security, Inc.
#

if(description)
{
 script_id(10212);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-0210", "CVE-1999-0704");
 script_bugtraq_id(235, 614);

 script_name(english:"automountd service");
 
 desc["english"] = "
The automountd service is running.

There is a bug in the Solaris rpc.statd
and automountd which allow an attacker
to execute any command remotely as root.

*** THIS VULNERABILITY WAS NOT TESTED 
*** AND MAY BE A FALSE POSITIVE

Solution : Disable your automountd and ask your
vendor if you are vulnerable.

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

RPC_PROG = 100099;
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
