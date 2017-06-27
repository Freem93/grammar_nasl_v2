# @DEPRECATED@
#
# Disabled on 2009-05-22
exit(0);

#
# (C) Tenable Network Security, Inc.
#

if(description)
{
 script_id(10229);
 script_version ("$Revision: 1.25 $");

 script_bugtraq_id(866, 8615);
 script_cve_id("CVE-1999-0977", "CVE-2003-0722");
 script_xref(name:"OSVDB", value:"2558");
 script_xref(name:"OSVDB", value:"4585");
 
 script_name(english:"sadmin service");
 
 desc["english"] = "
The sadmin RPC service is running. 
There is a bug in Solaris versions of this service that allow an intruder to
execute arbitrary commands on your system.  

Solution : disable this service

Risk factor : High";

 script_description(english:desc["english"]);
 
 script_summary(english:"checks the presence of a RPC service");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2012 Tenable Network Security, Inc.");
 script_family(english:"RPC");
 script_dependencie("rpc_portmap.nasl");
 if ( ! defined_func("bn_random") ) 
        script_dependencie("rpc_portmap.nasl");
 else
        script_dependencie("rpc_portmap.nasl", "solaris7_116456.nasl", "solaris7_x86_116457.nasl", "solaris8_116455.nasl", "solaris8_x86_116442.nasl", "solaris9_116453.nasl", "solaris9_x86_116454.nasl")
;
 script_require_keys("rpc/portmap");

 exit(0);
}

#
# The script code starts here
#


include("misc_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


if ( get_kb_item("BID-8615") ) exit(0);

RPC_PROG = 100232;
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
