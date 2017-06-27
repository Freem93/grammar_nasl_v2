#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(53335);
 script_version("$Revision: 1.2 $");
 script_cvs_date("$Date: 2011/08/29 18:35:21 $");

 script_name(english:"RPC portmapper (TCP)");
 script_summary(english:"Gets the port of the remote RPC portmapper");
 
 script_set_attribute(attribute:"synopsis", value:
"An ONC RPC portmapper is running on the remote host.");
 script_set_attribute(attribute:"description", value:
"The RPC portmapper is running on this port. 

The portmapper allows someone to get the port number of each RPC
service running on the remote host by sending either multiple lookup
requests or a DUMP request." );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/08");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");
 script_family(english:"RPC");

 script_dependencies("ping_host.nasl");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("sunrpc_func.inc");

# the portmaper
RPC_PROG = 100000;

port = 0;
kb_registered = 0;

if ( thorough_tests )
 ports = make_list(111, 32771);
else
 ports = make_list(111);

foreach p (ports)
{
  if (get_port_state(p))
    port = get_rpc_port3(program:RPC_PROG, protocol:IPPROTO_TCP, portmap:p, udp: FALSE);
  else
    port = 0;

  if (port)
  {
    if (p != 111) set_kb_item(name:"rpc/portmap/different_port", value:p);
    if (!kb_registered)
    {
      set_kb_item(name: "rpc/portmap/TCP", value: p);
      replace_kb_item(name:"rpc/portmap", value:p);
      kb_registered = 1;
    }
    register_service(port:p, proto:"rpc-portmapper", ipproto:"tcp");
    security_note(port:p);
  }
}
