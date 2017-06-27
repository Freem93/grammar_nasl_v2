#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description)
{
  script_id(10437);
  script_version("$Revision: 1.32 $");
  script_cvs_date("$Date: 2015/11/18 21:03:58 $");

  script_cve_id("CVE-1999-0554");
  script_osvdb_id(339);

  script_name(english:"NFS Share Export List");
  script_summary(english:"Gets a list of exported NFS shares");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote NFS server exports a list of shares."
  );

  script_set_attribute(
    attribute:'description',
    value:"This plugin retrieves the list of NFS exported shares."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Ensure each share is intended to be exported."
  );

  script_set_attribute(
    attribute:'see_also',
    value:"http://www.tldp.org/HOWTO/NFS-HOWTO/security.html"
  );

  script_set_attribute(
    attribute:'risk_factor',
    value:'None'
  );

  script_set_attribute(attribute:"plugin_publication_date", value:"2000/06/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");
  script_family(english:"RPC");
  script_dependencie("rpc_portmap.nasl");
  script_require_keys("rpc/portmap");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("nfs_func.inc");

global_var data, data_len, data_ptr;

function read_str()
{
  local_var len, pad, s;

  if (data_ptr + 4 > data_len)
    return NULL;
  len = getdword(blob:data, pos:data_ptr);
  data_ptr += 4;

  if (data_ptr + 4 > data_len)
    return NULL;
  s = substr(data, data_ptr, data_ptr + len - 1);
  data_ptr += len;

  pad = len % 4;
  if (pad > 0)
    data_ptr += 4 - pad;

  return s;
}

function read_int()
{
  local_var n;

  if (data_ptr + 4 > data_len)
    return NULL;
  n = getdword(blob:data, pos:data_ptr);
  data_ptr += 4;

  return n;
}

get_kb_item_or_exit("rpc/portmap");

port = get_rpc_port2(program:MOUNT_PROGRAM, protocol:IPPROTO_TCP);
if (port && get_tcp_port_state(port))
{
  proto = "tcp";
  soc = open_priv_sock_tcp(dport:port);
}
else
{
  proto = "udp";
  port = get_rpc_port2(program:MOUNT_PROGRAM, protocol:IPPROTO_UDP);
  if (port && get_udp_port_state(port))
    soc = open_priv_sock_udp(dport:port);
}

if (!port)
  audit(AUDIT_NOT_DETECT, "Mount Daemon");

if (!soc)
  audit(AUDIT_SOCK_FAIL, port, toupper(proto));

udp = (proto == "udp");
if (udp)
  set_kb_item(name:"nfs/port/udp", value:port);
set_kb_item(name:"nfs/proto", value:proto);

packet = rpc_packet(prog:MOUNT_PROGRAM, vers:1, proc:MOUNTPROC_EXPORT, udp:udp);
data = rpc_sendrecv(socket:soc, packet:packet, udp:udp);
data_len = strlen(data);
data_ptr = 0;

shares = make_list();
while (read_int())
{
  dir = read_str();
  if (isnull(dir))
    break;

  groups = make_list();
  while (read_int())
  {
    group = read_str();
    if (isnull(group))
      break;

    groups = make_list(groups, group);
  }

  share = dir + " " + join(groups, sep:", ");
  shares = make_list(shares, share);

  set_kb_item(name:"nfs/share_acl", value:share);
  set_kb_item(name:"nfs/exportlist", value:dir);
}

if (max_index(shares) == 0)
{
  set_kb_item(name:"nfs/noshares", value:TRUE);
  exit(0, "The remote host does not export any shares.");
}

report =
  '\nHere is the export list of ' + get_host_name() + ' :' +
  '\n  ' +
  '\n  ' + join(shares, sep:'\n  ') +
  '\n';

security_note(port:2049, extra:report, proto:proto);
