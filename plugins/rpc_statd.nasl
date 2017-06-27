# @DEPRECATED@
#
# Disabled on 2009-05-22
exit(0);

#
# (C) Tenable Network Security, Inc.
#

if(description)
{
 script_id(10235);
 script_version ("$Revision: 1.29 $");
 script_cve_id("CVE-1999-0018", "CVE-1999-0019", "CVE-1999-0493", "CVE-2004-1014");
 script_bugtraq_id(127, 450, 6831, 11785);
 script_xref(name:"OSVDB", value:"12240");
 
 script_name(english:"statd service");
 
 desc["english"] = "
The statd RPC service is running.  This service has a long history of 
security holes, so you should really know what you are doing if you decide
to let it run.

*** No security hole regarding this program have been tested, so
*** this might be a false positive.

Solution : We suggest that you disable this service.

Risk factor : High";

 script_description(english:desc["english"]);
 
 script_summary(english:"Checks the presence of a RPC service");
 
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
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


# RHEL not affected
if ( get_kb_item("Host/RedHat/release") ) exit(0);

RPC_PROG = 100024;
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
