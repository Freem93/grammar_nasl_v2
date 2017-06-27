#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15984);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2017/01/23 21:52:59 $");

 script_name(english:"NFS Share User Mountable");
 script_summary(english:"Checks for User Mountable NFS.");

 script_set_attribute(attribute:"synopsis", value:
"Nessus was able to access sensitive information from remote NFS shares
without having root privileges.");
 script_set_attribute(attribute:"description", value:
"Nessus was either able to mount some of the NFS shares exported by the
remote server or disclose potentially sensitive information such as a
directory listing. An attacker may exploit this issue to gain read and
possibly write access to files on remote host.

Note that root privileges were not required to mount the remote
shares since the source port to mount the shares was higher than 1024.");
 script_set_attribute(attribute:"solution", value:
"Configure NFS on the remote host so that only authorized hosts can
mount the remote shares. The remote NFS server should prevent mount
requests originating from a non-privileged port.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/16");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2017 Renaud Deraison (modified 2004 Michael Stone)");
 script_family(english:"RPC");

 script_dependencies("rpc_portmap.nasl", "showmount.nasl");
 script_require_keys("rpc/portmap", "nfs/exportlist");
 script_exclude_keys("nfs/noshares");

 exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("nfs_func.inc");
include("global_settings.inc");

######################################################################
# This plugin is a copy of nfs_mount.nasl with only the calls to
# 'open_priv_sock_udp()' and 'security_warning()' swapped out.
######################################################################

function open_soc(id, name)
{
  local_var port, soc;

  port = get_rpc_port2(program:id, protocol:IPPROTO_UDP);
  if (!port)
    audit(AUDIT_NOT_DETECT, name);

  if (!get_udp_port_state(port))
    audit(AUDIT_NOT_LISTEN, name, port);

  soc = open_sock_udp(port);
  if (!soc)
    audit(AUDIT_SOCK_FAIL, port, "UDP");

  return soc;
}

get_kb_item_or_exit("rpc/portmap");

shares = get_kb_list_or_exit("nfs/exportlist");
shares = make_list(shares);
if (max_index(shares) == 0)
  exit(1, "No exported shares were found.");

soc1 = open_soc(id:100005, name:"Mount Daemon");
soc2 = open_soc(id:100003, name:"NFS Daemon");

# RFC 1094, Section A.1: Introduction
#
# Version one of the mount protocol is used with version two of the
# NFS protocol. The only information communicated between these two
# protocols is the "fhandle" structure.
mountable = "";
foreach share (sort(shares))
{
  fid = nfs_mount(soc:soc1, share:share, ver:1);
  if (!fid)
    continue;

  mountable += '\n+ ' + share + '\n';

  content = nfs_readdir(soc:soc2, fid:fid, ver:2);
  if (max_index(content) != 0)
    mountable += '  + Contents of ' + share + ' : \n';

  foreach c (sort(content))
    mountable += '    - ' + c + '\n';

  nfs_umount(soc:soc1, share:share);
}

close(soc1);
close(soc2);

if (!mountable)
  exit(1, "Failed to mount any user-mountable NFS shares on the remote host.");

port = get_rpc_port2(program:100003, protocol:IPPROTO_UDP);

report =
  '\nPotentially sensitive information was able to be obtained from the' +
  '\nfollowing shares without root privileges :' +
  '\n' + mountable;
security_report_v4(port:port, severity:SECURITY_HOLE, proto:"udp", extra:report);
