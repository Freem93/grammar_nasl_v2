#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
 script_id(11356);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2014/02/19 01:34:32 $");
 script_cve_id("CVE-1999-0170", "CVE-1999-0211", "CVE-1999-0554");
 script_osvdb_id(339, 8750, 11516);

 script_name(english:"NFS Exported Share Information Disclosure");
 script_summary(english:"Checks for NFS");

 script_set_attribute(
  attribute:"synopsis",
  value:
"It is possible to access NFS shares on the remote host."
 );
 script_set_attribute(
  attribute:"description",
  value:
"At least one of the NFS shares exported by the remote server could be
mounted by the scanning host.  An attacker may be able to leverage
this to read (and possibly write) files on remote host."
 );
 script_set_attribute(
  attribute:"solution",
  value:
"Configure NFS on the remote host so that only authorized hosts can
mount its remote shares."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'NFS Mount Scanner');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1985/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/12");

 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 script_family(english:"RPC");

 script_dependencies("rpc_portmap.nasl", "showmount.nasl");
 script_require_keys("rpc/portmap", "nfs/exportlist");
 script_exclude_keys("nfs/noshares");

 exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("nfs_func.inc");
include("sunrpc_func.inc");

function open_soc(id, name)
{
  local_var port, soc;

  port = get_rpc_port2(program:id, protocol:IPPROTO_UDP);
  if (!port)
    audit(AUDIT_NOT_DETECT, name);

  if (!get_udp_port_state(port))
    audit(AUDIT_NOT_LISTEN, name, port);

  soc = open_priv_sock_udp(dport:port);
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

  # Due to a bug in Nessus, we need to open the NFS socket up
  # after the mount socket has already been used.
  if (soc2)
    close(soc2);
  soc2 = open_soc(id:100003, name:"NFS Daemon");

  mountable += '\n+ ' + share + '\n';
  content = nfs_readdir(soc:soc2, fid:fid, ver:2);
  if (max_index(content) != 0)
    mountable += '  + Contents of ' + share + ' : \n';

  foreach c (sort(content))
    mountable += '    - ' + c + '\n';

  nfs_umount(soc:soc1, share:share);
}

close(soc1);

if (!mountable)
  exit(1, "Failed to mount any NFS shares on the remote host.");

report =
  '\nThe following NFS shares could be mounted :' +
  '\n' + mountable;
security_warning(port:2049, proto:"udp", extra:report);
