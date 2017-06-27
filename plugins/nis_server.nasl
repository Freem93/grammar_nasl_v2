#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(10158);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2014/02/19 01:34:32 $");

 script_name(english:"NIS Server Detection");
 script_summary(english:"Checks the presence of a RPC service");

 script_set_attribute(attribute:"synopsis", value:
"An NIS server is running on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is an NIS (Network Information Service) server.  NIS
is used to share usernames, passwords, and other sensitive information
among the hosts claiming to be within a given NIS domain and passes
this information over the network unencrypted.");
 script_set_attribute(attribute:"solution", value:
"Filter traffic connecting to the portmapper and to the NIS server
itself.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/30");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english:"RPC");
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");
include("sunrpc_func.inc");


RPC_PROG = 100004;
tcp = 0;
port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}

if(port)
{
 if(tcp)security_note(port);
 else security_note(port:port, protocol:"udp");
}
