#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48264);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/01/13 15:34:51 $");

  script_cve_id("CVE-2010-2965");
  script_bugtraq_id(42158);
  script_osvdb_id(66842);
  script_xref(name:"CERT", value:"362332");
  script_xref(name:"ICSA", value:"10-214-01");

  script_name(english:"VxWorks WDB Debug Service Detection");
  script_summary(english:"Sends a CONNECT request to VxWorks debug agent");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands can be run on this port." );
  script_set_attribute(attribute:"description", value:
"A VxWorks WDB Debug Agent is running on this host. 

Using this service, it is possible to read or write any memory zone or
execute arbitrary code on the host.  An attacker can use this flaw to
take complete control of the affected device." );
  script_set_attribute(attribute:"solution", value: 
"Disable the debug agent or contact the device's vendor for a patch." );
  script_set_attribute(attribute:"vuln_publication_date", value: "2010/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/06");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
  script_family(english:"RPC");
  script_dependencies("rpcinfo.nasl");
  exit (0);

}

include("global_settings.inc");
include("misc_func.inc");
include("sunrpc_func.inc");
include("network_func.inc");

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

wdbport = 0x4321;	# dec = 17185
wdbprog = 0x55555555;	# dec = 1431655765
wdbvers = 1;

global_var	seq_nb, host_id;
seq_nb = 0;
host_id = rand() % 65534 + 1;

function wdb_packet(proc, data)
{
  local_var	pkt, len, i, xid, sum, seqh;

  len = strlen(data) + 11 * 4;	# Do not count XID
  sum = 0;

  # The protocol is a slightly modified version of Sun RPC
  xid = rand();
  seq_nb ++;
  seqh = (host_id << 16) | seq_nb;

  pkt = strcat(
    mkdword(xid)	+ # 0: XID
    mkdword(0)		+ # 1: Call
    mkdword(2)		+ # 2: RPC version = 2
    mkdword(wdbprog)	+ # 3: program
    mkdword(wdbvers)	+ # 4: program version
    mkdword(proc)	+ # 5: Procedure
    # Credentials
    mkdword(0)		+ # 6
    mkdword(0)		+ # 7
    # Verifier    
    mkdword(0)		+ # 8
    mkdword(0)		+ # 9
    #
    mkdword(0)		+ # 10: Checksum
    mkdword(len)	+ # 11
    mkdword(seqh)	+ # 12
    data );		  # 13

  sum = ip_checksum(data: pkt);
  # Replace checksum
  return substr(pkt, 0, 39) + mkdword(sum) + substr(pkt, 44);
}


#if (!get_udp_port_state(wdbport)) exit(0, "UDP port "+wdbport+" is closed.");
if (known_service(port:wdbport, ipproto:"udp")) exit(0, "The service listening on UDP port "+wdbport+" is already known.");

soc = open_sock_udp(wdbport);
if (!soc) exit(1, "Cannot create UDP socket to "+wdbport+".");

# 0: Ping
# 1: Connect

blob = wdb_packet(proc: 1, data: "");

r =  rpc_sendrecv (socket: soc, packet: blob, udp: 1);
close(soc);

if (isnull(r))
  exit(1, "RPC error from port "+wdbport+" : rep=" + __rpc_reply_stat + " acc="+ __rpc_accept_stat);

e = '';

# Skip WDB wrapper and parse the remaining data with XDR
# Verifying this header is useless: I get a zero-ed zone from the agent!

register_stream(s: substr(r, 12));

av = xdr_getstring();
mtu = xdr_getdword();
mode = xdr_getdword();;
e = strcat(e, '\nAgent version : ', av, '\nMTU : ', mtu, '\nAgent mode : ', mode);

rtt = xdr_getdword();
rtv = xdr_getstring();
e = strcat(e, '\nRun time type : ', rtt);
if (rtt == 0) e += ' (standalone WDB agent)';
else if (rtt == 1) e+= ' (WDB agent in VxWorks)';
e = strcat(e, '\nRun time version : ', rtv);

set_kb_item(name: "Host/VxWorks/RunTimeVersion", value: rtv);

x = xdr_getdword();
e = strcat(e , '\nCPU type : ', x);
x = xdr_getdword();
if (x) e += '\nFP coprocessor is installed.'; else e += '\nNo FP coprocessor.';
x = xdr_getdword();
if (x) e += '\nTarget can write protect memory.'; else e += '\nTarget cannot write protect memory.';
x = xdr_getdword();
e = strcat(e , '\nPage size : ', x);
x = xdr_getdword();
e = strcat(e , '\nEndianness : ', x);

bn = xdr_getstring();
bp = xdr_getstring();
if (bn) e = strcat(e, '\nBoard support package name : ', bn);
if (bp) e = strcat(e, '\nBoot file path : ', bp);

x = xdr_getdword();
e = strcat(e , '\nMemory base address : ', x);
x = xdr_getdword();
e = strcat(e , '\nMemory size : ', x);

e += '\n';

register_service(port:wdbport, ipproto:"udp", proto:"vxworks_wdb");

if (report_verbosity == 0)
  security_hole(port: wdbport, proto: "udp");
else
  security_hole(port: wdbport, proto: "udp", extra: e);

if (COMMAND_LINE) display(e);
