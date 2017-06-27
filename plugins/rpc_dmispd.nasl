# @DEPRECATED@
#
# Disabled on 2009-05-22
exit(0);

#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# Modified by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details 
#

if(description)
{
 script_id(11405);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2002-0391");
 script_bugtraq_id(5356);

 script_name(english:"dmisd service");
 
 desc["english"] = "
The dmisd RPC service is running. 

This service uses the function xdr_array() of the RPC library.
It turns out that some older versions of the RPC library
are vulnerable to an integer overflow in this function,
which could allow an attacker to gain root privileges on
this host.

*** No security hole regarding this program has been tested, so
*** this might be a false positive.

Solution : We suggest that you disable this service.
See also : http://www.cert.org/advisories/CA-2002-25.html
Risk factor : High";


 script_description(english:desc["english"]);
 
 script_summary(english:"Checks the presence of a RPC service");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
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




RPC_PROG = 300598;
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
