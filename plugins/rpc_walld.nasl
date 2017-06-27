# @DEPRECATED@
#
# Disabled on 2009-05-22
exit(0);

#
# (C) Tenable Network Security, Inc.
#

if(description)
{
 script_id(10240);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-1999-0181");
 script_xref(name:"OSVDB", value:"11522");
 script_xref(name:"OSVDB", value:"11570");
 
 script_name(english:"walld service");
 
 desc["english"] = "
The walld RPC service is running.  It is usually used by the administrator
to tell something to the users of a network by making a message appear
on their screen.

Since this service lacks any kind of authentication, an attacker
may use it to trick users into doing something (change their password,
leave the console, or worse), by sending a message which would appear to be
written by the administrator.

It can also be used as a denial of service attack, by continually sending 
garbage to the users screens, preventing them from working properly.

Solution : Disable this service.
Risk factor : Medium";

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
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);



RPC_PROG = 100008;
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
