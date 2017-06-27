#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(11111);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2011/05/24 20:37:08 $");

  script_name(english:"RPC Services Enumeration");
  script_summary(english:"Enumerates the remote RPC services");

  script_set_attribute(attribute:"synopsis", value:
"An ONC RPC service is running on the remote host." );
  script_set_attribute(attribute:"description", value:
"By sending a DUMP request to the portmapper, it was possible to
enumerate the ONC RPC services running on the remote port.  Using this
information, it is possible to connect and bind to each service by
sending an RPC request to the remote port." );
  script_set_attribute(attribute:"risk_factor", value: "None" );
  script_set_attribute(attribute:"solution", value: "n/a" );
  script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/24");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
  script_family(english: "Service detection");

  script_dependencies("rpc_portmap.nasl");
  script_require_ports("rpc/portmap");
  exit (0);
}


include("global_settings.inc");
include("misc_func.inc");
include ("sunrpc_func.inc");

# we use 2 lists to speed up the search / service registering
global_var tcp_rpc_server, udp_rpc_server;

function add_rpc_server (p, v, proto, port)
{
 local_var list, entry, pos;

 entry = string(port);

 if (proto == IPPROTO_TCP)
 {
  if (isnull(tcp_rpc_server[entry]))
  {
   list = NULL;
   pos = 0;
  }
  else
  {
   list = tcp_rpc_server[entry];
   pos = max_index(list);
  }

  list[pos] = make_list(p, v);
  tcp_rpc_server[entry] = list;
 }
 else if (proto == IPPROTO_UDP)
 {
  if (isnull(udp_rpc_server[entry]))
  {
   list = NULL;
   pos = 0;
  }
  else
  {
   list = udp_rpc_server[entry];
   pos = max_index(list);
  }

  list[pos] = make_list(p, v);
  udp_rpc_server[entry] = list;
 }
}

portmap = get_kb_item("rpc/portmap/TCP");
if (portmap)
  udp = 0;
else
{
  udp = 1;
portmap = get_kb_item("rpc/portmap");
if (!portmap) exit(0, "No portmapper");
}

if (! udp)
{
  if (! get_tcp_port_state(portmap)) exit(0, "TCP port "+portmap+" is not open.");
  soc = open_sock_tcp (portmap);
}
else
{
  if (! get_udp_port_state(portmap)) exit(0, "UDP port "+portmap+" is not open.");
  soc = open_sock_udp (portmap);
}
if (!soc) exit(0, "Connection refused on port "+portmap);
 

data = NULL;

# portmapper : prog:100000 version:2 procedure:DUMP(4)

packet = rpc_packet (prog:100000, vers:2, proc:0x04, data:data, udp: udp);
data = rpc_sendrecv (socket:soc, packet:packet, udp: udp);

if (isnull(data))
{
  close(soc);
  exit(1, "No answer to RPC DUMP");
}

register_stream(s:data);

tcp_rpc_server = udp_rpc_server = NULL;

repeat
{
 value = xdr_getdword();
 if (value)
 {
  program = xdr_getdword();
  version = xdr_getdword();
  protocol = xdr_getdword();
  port = xdr_getdword();

  if (stream_error()) break;

  add_rpc_server (p:program, v:version, proto:protocol, port:port);
 }
}
until (!value || value == 0);


# first we list/register TCP services
foreach entry (keys(tcp_rpc_server))
{
 report = NULL;

 foreach svc (tcp_rpc_server[entry])
 {
  report += string(" - program: ", svc[0]);

  if (!isnull(sunrpc_prog_nb[string(svc[0])]))
  {
   name = sunrpc_prog_nb[string(svc[0])];
   report += string(" (",name,")");

   register_service(port:int(entry), proto:string("rpc-",name));
  }
  else
   register_service(port:int(entry), proto:string("rpc-",svc[0]));


  report += string(", version: ", svc[1], "\n");
  set_kb_item(name:'rpc/'+name+'/tcp/ver', value:svc[1]);
 }

 report = string ("\n",
		"The following RPC services are available on TCP port ", entry, " :\n\n",
		report);

 security_note (port:int(entry), extra:report);
}

# then UDP services
foreach entry (keys(udp_rpc_server))
{
 report = NULL;

 foreach svc (udp_rpc_server[entry])
 {
  report += string(" - program: ", svc[0]);

  if (!isnull(sunrpc_prog_nb[string(svc[0])]))
  {
   name = sunrpc_prog_nb[string(svc[0])];
   report += string(" (",name,")");

   register_service(port:int(entry), proto:string("rpc-",name), ipproto:"udp");
  }
  else
   register_service(port:int(entry), proto:string("rpc-",svc[0]), ipproto:"udp");

  report += string(", version: ", svc[1], "\n");
  set_kb_item(name:'rpc/'+name+'/udp/ver', value:svc[1]);
 }

 report = string ("\n",
		"The following RPC services are available on UDP port ", entry, " :\n\n",
		report);

 security_note (port:int(entry), extra:report, proto:"udp");

}

