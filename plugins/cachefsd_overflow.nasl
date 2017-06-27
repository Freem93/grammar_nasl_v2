#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10951);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
 script_cve_id("CVE-2002-0084");
 script_bugtraq_id(4631);
 script_osvdb_id(17477);

 script_name(english:"Solaris cachefsd fscache_setup Function Remote Overflow");
 script_summary(english:"Checks the presence of a RPC service");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote RPC service has multiple buffer overflow vulnerabilities."
 );
 script_set_attribute(attribute:"description", value:
"The cachefsd RPC service is running on this port.

Multiple vulnerabilities exist in this service.  At least one heap
overflow vulnerability can be exploited remotely to obtain root
privileges by sending a long directory and cache name request to the
service.  A buffer overflow can result in root privileges from local
users exploiting the fscache_setup function with a long mount
argument

Solaris 2.5.1, 2.6, 7 and 8 are vulnerable to this issue. Other
operating systems might be affected as well.

*** Nessus did not check for this vulnerability,
*** so this might be a false positive." );
 # https://web.archive.org/web/20020616080638/http://archives.neohapsis.com/archives/vulnwatch/2002-q2/0048.html
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?082477b0"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://download.oracle.com/sunalerts/1000988.1.html"
 );
 script_set_attribute(
   attribute:"solution",
   value:"Apply the appropriate patch referenced in the vendor's advisory."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/04/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/05/08");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");
include("global_settings.inc");
include("sunrpc_func.inc");

if ( report_paranoia == 0 ) exit(0);


#
# This is kinda lame but there's no way (yet) to remotely determine if
# this service is vulnerable to this flaw.
#
RPC_PROG = 100235;
tcp = 0;
port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}

if(port)
{
 if(tcp)security_hole(port);
 else security_hole(port:port, protocol:"udp");
}
