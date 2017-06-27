# @DEPRECATED@
#
# Disabled on 2009-05-22
exit(0);

#
# (C) Tenable Network Security, Inc.
#

if(description)
{
 script_id(10219);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-0832", "CVE-2002-0830");
 script_bugtraq_id(782);
 script_xref(name:"OSVDB", value:"11279");

 script_name(english:"nfsd service");
 
 desc["english"] = "
The nfsd RPC service is running.  In the past, this service has 
had bugs which allow an intruder to execute arbitrary commands 
on your system. In addition, FreeBSD 4.6.1 RELEASE-p7 and earlier, 
NetBSD 1.5.3 and earlier have a bug wherein sending a zero length 
packet to the RPC service will cause the operating system to hang.

Solution : Make sure that you have the latest version of nfsd

Risk factor : High";

 script_description(english:desc["english"]);
 
 script_summary(english:"checks the presence of a RPC service");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"RPC");
 if ( ! defined_func("bn_random") )
 	script_dependencie("rpc_portmap.nasl");
 else
 	script_dependencie("rpc_portmap.nasl", "ssh_get_info.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

#
# The script code starts here
#


include("misc_func.inc");
include("freebsd_package.inc");
include('global_settings.inc');

if ( report_paranoia < 2 ) exit(0);

if ( get_kb_item("Host/RedHat/release") ) exit(0);
if ( get_kb_item("Host/Solaris/Version") ) exit(0);
freebsd = get_kb_item("Host/FreeBSD/release");
if ( freebsd )
{
 if ( pkg_cmp(pkg:freebsd, reference:"FreeBSD-4.6.1_7") >= 0 ) exit(0);
}

RPC_PROG = 100003;
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
