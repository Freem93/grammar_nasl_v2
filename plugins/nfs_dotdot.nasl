#
# (C) Tenable Network Security, Inc.
#

# This is the implementation of an oooold attack.
#

include( 'compat.inc' );

if (description)
{
  script_id(11357);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/02/16 21:23:30 $");
  script_cve_id("CVE-1999-0166");
  script_osvdb_id(11630);

  script_name(english:"Multiple Vendor NFS CD Command Arbitrary File/Directory Access");
  script_summary(english:"Checks for the NFS .. attack");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote NFS server allows users to use a 'cd ..' command
to access other directories besides the NFS file system.

An attacker may use this flaw to read every file on this host."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Create a dedicated partition for your NFS exports, and contact your
vendor for a patch."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");


 script_set_attribute(attribute:"vuln_publication_date", value:"1991/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
  script_family(english:"RPC");
  script_dependencie("rpc_portmap.nasl", "showmount.nasl");
  script_require_keys("rpc/portmap");
  exit(0);
}

#

include("misc_func.inc");
include("nfs_func.inc");
include("sunrpc_func.inc");

mountable = NULL;


list = get_kb_list("nfs/exportlist");
if(isnull(list))exit(0);
shares = make_list(list);


port = get_rpc_port2(program:100005, protocol:IPPROTO_UDP);
if ( ! port ) exit(0);
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
soc = open_priv_sock_udp(dport:port);

port2 = get_rpc_port2(program:100003, protocol:IPPROTO_UDP);
if ( ! port2 ) exit(0);
if (! get_udp_port_state(port2)) exit(0, "UDP port "+port2+" is not open.");
soc2 = open_priv_sock_udp(dport:port2);

if(!soc || !soc2)exit(0);


foreach share (shares)
{
 fid = nfs_mount(soc:soc, share:share);
 if(fid)
 {
  dir1 = nfs_readdir(soc:soc2, fid:fid);
  fid2 = nfs_lookup(soc:soc2, fid:fid, file:"..");
  dir3 = dir2 = nfs_readdir(soc:soc2, fid:fid2);
  hash = make_list();

  foreach d (dir1)
  {
   hash[d] = 1;
  }

  foreach d (dir2)
  {
   if(!hash[d]){
   	report =
"The remote NFS server allows users to use a 'cd ..' command
to access other directories besides the NFS file system.

The listing of " + share + ' is :\n';

  foreach d (dir1)
  {
   report += '- ' + d + '\n';
  }

  report += string("\nAfter having sent a 'cd ..' request, the list of files is : \n");

  foreach d (dir3)
  {
   report += '- ' + d + '\n';
  }


report += "An attacker may use this flaw to read every file on this host";
   	security_warning(port:port, extra:report, proto:"udp");
	nfs_umount(soc:soc, share:share);
	exit(0);
	}
  }


  nfs_umount(soc:soc, share:share);
  close(soc);
  close(soc2);
  exit(0);
 }
}

close(soc);
close(soc2);
