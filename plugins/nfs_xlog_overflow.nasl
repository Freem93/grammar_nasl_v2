#
# (C) Tenable Network Security, Inc.
#

#
# This check is destructive by its very nature, as we need to check for a
# off-by-one overflow. Very few distributions are actually affected,
# in spite of all the advisories that have been published, as the exploitability
# of this flaw actually depends on the version of gcc which has been used
# to compile nfs-utils.
#

include( 'compat.inc' );

if (description)
{
	script_id(11800);
	script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2017/02/16 21:23:30 $");
	script_cve_id("CVE-2003-0252");
	script_bugtraq_id(8179);
	script_osvdb_id(2317);
	script_xref(name:"RHSA", value:"2003:206-01");
	script_xref(name:"SuSE", value:"SUSE-SA:2003:031");

	script_name(english:"Linux NFS utils package (nfs-utils) mountd xlog Function Off-by-one Remote Overflow");
	script_summary(english:"Checks for NFS");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote rpc.mountd daemon is vulnerable to an off-by-one overflow
which could be exploited by an attacker to gain a root shell on this
host."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to the latest version of nfs-utils"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://marc.info/?l=bugtraq&m=105820223707191&w=2'
  );

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/07/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
	script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
	script_family(english:"RPC");
	script_dependencie("rpc_portmap.nasl", "showmount.nasl", "os_fingerprint.nasl");
	script_require_keys("rpc/portmap");
	exit(0);
}



include("misc_func.inc");
include("nfs_func.inc");
include("global_settings.inc");
include("sunrpc_func.inc");

#
# Returns <1> if the remote mountd replies anything to our
# requests.
#
function zmount(soc, share)
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
  if(strlen(r) > 0) return(1);
  else return(0);
}

port = get_rpc_port2(program:100005, protocol:IPPROTO_UDP);
if ( ! port ) exit(0);
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
soc = open_priv_sock_udp(dport:port);
if(!soc)exit(0);

if(safe_checks())
{
 os = get_kb_item("Host/OS");
 if(os && "Linux 2.4" >!< os)exit(0);

 if(zmount(soc:soc, share:"/nessus"))
 {

  if ( report_paranoia < 2 ) exit(0);
  rep = "
The remote rpc.mountd daemon might be vulnerable to an off-by-one overflow
which may be exploited by an attacker to gain a root shell on this
host.

*** Since safe checks are enabled, Nessus did not actually check
*** for this flaw, so it might be a false positive.
*** At this time, this flaw is known to affect only older Linux distributions
*** such as RedHat 6.1 or 6.2.

Solution : Upgrade to the latest version of nfs-utils
Risk factor : High";

 security_hole(port:port, extra:rep, proto:"udp");
 }
 close(soc);
 exit(0);
}

if(zmount(soc:soc, share:"/nessus"))
{
 zmount(soc:soc, share:"/" + crap(length:1023, data:raw_string(0xFF)));
 if(zmount(soc:soc, share:"/nessus") == 0 )
 {
  security_hole(port:port, proto:"udp");
 }
}

close(soc);
