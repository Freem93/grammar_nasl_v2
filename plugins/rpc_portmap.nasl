#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10223);
 script_version("$Revision: 1.36 $");
 script_cvs_date("$Date: 2014/02/19 01:34:32 $");
 script_cve_id("CVE-1999-0632");

 script_name(english:"RPC portmapper Service Detection");
 script_summary(english:"Gets the port of the remote rpc portmapper");

 script_set_attribute(attribute:"synopsis", value:
"An ONC RPC portmapper is running on the remote host.");
 script_set_attribute(attribute:"description", value:
"The RPC portmapper is running on this port.

The portmapper allows someone to get the port number of each RPC
service running on the remote host by sending either multiple lookup
requests or a DUMP request.");
 script_set_attribute(attribute:"risk_factor", value: "None");
 script_set_attribute(attribute:"solution", value: "n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/19");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
 script_family(english:"RPC");
 script_dependencies("ping_host.nasl");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("sunrpc_func.inc");

ports = make_list(111);
if (thorough_tests)
  ports = make_list(ports, 32771);

found = FALSE;
foreach p (ports)
{
  if (!get_udp_port_state(p))
    continue;

  port = get_rpc_port2(program:PMAP_PROGRAM, protocol:IPPROTO_UDP, portmap:p);
  if (!port)
    continue;

  if (p != 111)
    set_kb_item(name:"rpc/portmap/different_port", value:p);

  if (!found)
  {
    set_kb_item(name:"rpc/portmap", value:p);
    found = TRUE;
  }

  register_service(port:p, proto:"rpc-portmapper", ipproto:"udp");
  security_note(port:p, proto:"udp");
}

if (!found)
  audit(AUDIT_NOT_DETECT, "RPC Portmapper");
