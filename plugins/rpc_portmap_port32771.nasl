#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(20759);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-1999-0632", "CVE-1999-0189");
 script_bugtraq_id(205);
 script_osvdb_id(8727);

 script_name(english:"RPC rpcbind Non-standard Port Assignment Filter Bypass");
 
 script_set_attribute(attribute:"synopsis", value:
"An ONC RPC portmapper is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"The RPC portmapper is running on this port.

The portmapper allows someone to get the port number of each RPC
service running on the remote host by sending either multiple lookup
requests or a DUMP request. 

This service should only run on port 111. However on some operating
systems it also listens on different UDP ports. This might allow an
attacker to circumvent firewall rules." );
 script_set_attribute(attribute:"solution", value:
"Disable this service if RPC are not used, or update your firewall rules
if needed.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "1997/06/04");
 script_cvs_date("$Date: 2017/02/16 21:23:30 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Gets the port of the remote rpc portmapper");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");
 script_family(english:"RPC"); 
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap/different_port");
 exit(0);
}

ports = get_kb_list("rpc/portmap/different_port");
if ( isnull(ports) ) exit(0);
foreach p ( make_list(ports) ) if ( p != 111 ) security_warning(port:p, proto:"udp");
