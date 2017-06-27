# @DEPRECATED@
#
# Disabled on 2009-05-22
exit(0);

#
# (C) Tenable Network Security, Inc.
#

if(description)
{
 script_id(10787);
 script_version ("$Revision: 1.34 $");
 script_cve_id("CVE-2002-0677", "CVE-2001-0717", "CVE-2002-0679");
 script_bugtraq_id(3382, 5082);
 script_xref(name:"OSVDB", value:"4504");
 script_xref(name:"OSVDB", value:"4506");
 script_xref(name:"OSVDB", value:"4507");
 
 script_name(english:"tooltalk format string");

 desc["english"] = "
The tooltalk RPC service is running.

There is a format string bug in many versions
of this service, which allow an attacker to gain
root remotely.

In addition to this, several versions of this service
allow remote attackers to overwrite arbitrary memory
locations with a zero and possibly gain privileges
via a file descriptor argument in an AUTH_UNIX 
procedure call which is used as a table index by the
_TT_ISCLOSE procedure.

*** This warning may be a false positive since the presence
*** of the bug was not verified locally.
    
Solution : Disable this service or patch it
See also : CERT Advisories CA-2001-27 and CA-2002-20

Risk factor : High";


 script_description(english:desc["english"]);

 script_summary(english:"Checks the presence of a RPC service");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2012 Tenable Network Security, Inc.");
 script_family(english:"RPC"); 
 if ( ! defined_func("bn_random") )
 	script_dependencie("rpc_portmap.nasl", "os_fingerprint.nasl");
 else
 	script_dependencie("rpc_portmap.nasl", "os_fingerprint.nasl", "solaris251_104489.nasl", "solaris251_x86_105496.nasl", "solaris26_105802.nasl", "solaris26_x86_105803.nasl", "solaris7_107893.nasl", "solaris7_x86_107894.nasl", "solaris8_110286.nasl", "solaris8_x86_110287.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

#
# The script code starts here
#


include("misc_func.inc");
include("global_settings.inc");



if ( get_kb_item("BID-3382") ) exit(0);
version = get_kb_item("Host/Solaris/Version");
if ( version )
{
	 if ( ereg(pattern:"^5\.(9|1[0-9])", string:version)) exit(0);
	else
 	 if ( ereg(pattern:"^5\.[0-8]([^0-9]|$)", string:version) ) vuln ++;
}
else {
 version = get_kb_item("Host/OS");
 if ( version )
	{
	if ( ereg(pattern:"Solaris (9|1[0-9])", string:version)) exit(0);
	else if ( ereg(pattern:"Solaris (2\.|7|8)") ) vuln ++;
	}
}


if ( report_paranoia < 2  && ! vuln )  exit(0);



RPC_PROG = 100083;
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
