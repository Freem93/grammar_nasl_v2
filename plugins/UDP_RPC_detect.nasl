#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(53334);
 script_version("$Revision: 1.5 $");
 script_cvs_date("$Date: 2011/08/29 17:42:18 $");

 script_name(english:"Detect RPC over UDP");
 script_summary(english:"Call RPC #0 on all open UDP ports");
 
 script_set_attribute(attribute:"synopsis", value:
"A RPC service is running on this port." );
 script_set_attribute(attribute:"description", value:
"This service answered to a RPC procedure #0 call.

For whatever reason, it was not registered by the portmapper or Nessus 
could not query to the portmapper (e.g. if port 111 is filtered or not
scanned)." );
 script_set_attribute(attribute:"solution", value:
"N/A" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/08");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");
 script_family(english:"RPC");

 script_dependencie("rpcinfo.nasl");
 script_require_keys("Host/udp_scanned");
 script_exclude_keys("global_settings/disable_service_discovery", "rpc/portmap");
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("sunrpc_func.inc");

if ( !thorough_tests ) exit(0);

global_var	soc;

function test(port)
{
 local_var	pack, r;

 if (! get_udp_port_state(port)) return 0;
 if (! service_is_unknown(port:port, ipproto:'udp')) return 0;

 if (soc) close(soc);
 soc = open_sock_udp(port);
 if (! soc) return 0;

 pack = rpc_packet(prog:0, vers:2, proc:0, udp:1);
 r = rpc_sendrecv (socket:soc, packet:pack, udp:1);
 if (!r) # error
 {
   if (rpc_reply_stat() == 0 && rpc_accept_stat() == 0)
     return 0;
 }

 security_note(port:port, proto:'udp');
 register_service(port:port, proto:'rpc', ipproto:'udp');
 return 1;
}

#

if (get_kb_item("global_settings/disable_service_discovery")  )
  exit(0, "Service discovery is disabled.");

# If the portmapper answered, we do not need to run this script, except
# in thorough mode, in case there's a RPC server which did not register
if (!thorough_tests && get_kb_item("rpc/portmap"))
 exit(0, "The RPC portmapper answered.");

# Only the portmapper (111) and NFS (2049) appear to be stable on every OS.
# However, some services below 32787 (not 32767!) are reasonably stable on a
# given OS -- for example, services like rused, rsprayd... may be started by
# inetd on *BSD or Solaris.
# Services above that port are placed randomly.

foreach p (scanned_ports_list(ipproto:'udp'))
{
  if (thorough_tests || sunrpc_common_ports[p])
     test(port:p);
}
# Cleanup
if (soc) close(soc);
