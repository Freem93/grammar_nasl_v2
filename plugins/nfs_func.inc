###
# (C) Tenable Network Security, Inc.
#
# @NOGPL@
#
# $Revision: 1.15 $
###

include ("sunrpc_func.inc");

######################################################################
# Legacy Functions
######################################################################

function padsz(len)
{
  return xdr_pad_len(len);
}

function rpcpad(pad)
{
  return crap(data:'\0', length:pad);
}

function rpclong(val)
{
  return xdr_long(val);
}

function str2long(idx, val)
{
  return getdword(val, pos:idx, order:BYTE_ORDER_BIG_ENDIAN);
}

######################################################################
# Network File System Functions
######################################################################

###
# RFC 1094, Section A.5: Server Procedures
#
# RFC 1813 (NFSv3) maintains keeps this mapping.
###
global_var MOUNT_PROGRAM;
MOUNT_PROGRAM = 100005;

global_var
  MOUNTPROC_NULL,
  MOUNTPROC_MNT,
  MOUNTPROC_DUMP,
  MOUNTPROC_UMNT,
  MOUNTPROC_UMNTALL,
  MOUNTPROC_EXPORT;

MOUNTPROC_NULL = 0;
MOUNTPROC_MNT = 1;
MOUNTPROC_DUMP = 2;
MOUNTPROC_UMNT = 3;
MOUNTPROC_UMNTALL = 4;
MOUNTPROC_EXPORT = 5;

###
# RFC 1094, Section 2.2: Server Procedures
###
global_var NFS_PROGRAM;
NFS_PROGRAM = 100003;

global_var
  NFSPROC_NULL,
  NFSPROC_GETATTR,
  NFSPROC_SETATTR,
  NFSPROC_ROOT,
  NFSPROC_LOOKUP,
  NFSPROC_READLINK,
  NFSPROC_READ,
  NFSPROC_WRITECACHE,
  NFSPROC_WRITE,
  NFSPROC_CREATE,
  NFSPROC_REMOVE,
  NFSPROC_RENAME,
  NFSPROC_LINK,
  NFSPROC_SYMLINK,
  NFSPROC_MKDIR,
  NFSPROC_RMDIR,
  NFSPROC_READDIR,
  NFSPROC_STATFS;

NFSPROC_NULL = 0;
NFSPROC_GETATTR = 1;
NFSPROC_SETATTR = 2;
NFSPROC_ROOT = 3;
NFSPROC_LOOKUP = 4;
NFSPROC_READLINK = 5;
NFSPROC_READ = 6;
NFSPROC_WRITECACHE = 7;
NFSPROC_WRITE = 8;
NFSPROC_CREATE = 9;
NFSPROC_REMOVE = 10;
NFSPROC_RENAME = 11;
NFSPROC_LINK = 12;
NFSPROC_SYMLINK = 13;
NFSPROC_MKDIR = 14;
NFSPROC_RMDIR = 15;
NFSPROC_READDIR = 16;
NFSPROC_STATFS = 17;

###
# RFC 1813, Section 3: Server Procedures
###
global_var
  NFSPROC3_NULL,
  NFSPROC3_GETATTR,
  NFSPROC3_SETATTR,
  NFSPROC3_LOOKUP,
  NFSPROC3_ACCESS,
  NFSPROC3_READLINK,
  NFSPROC3_READ,
  NFSPROC3_WRITE,
  NFSPROC3_CREATE,
  NFSPROC3_MKDIR,
  NFSPROC3_SYMLINK,
  NFSPROC3_MKNOD,
  NFSPROC3_REMOVE,
  NFSPROC3_RMDIR,
  NFSPROC3_RENAME,
  NFSPROC3_LINK,
  NFSPROC3_READDIR,
  NFSPROC3_READDIRPLUS,
  NFSPROC3_FSSTAT,
  NFSPROC3_FSINFO,
  NFSPROC3_PATHCONF,
  NFSPROC3_COMMIT;

NFSPROC3_NULL = 0;
NFSPROC3_GETATTR = 1;
NFSPROC3_SETATTR = 2;
NFSPROC3_LOOKUP = 3;
NFSPROC3_ACCESS = 4;
NFSPROC3_READLINK = 5;
NFSPROC3_READ = 6;
NFSPROC3_WRITE = 7;
NFSPROC3_CREATE = 8;
NFSPROC3_MKDIR = 9;
NFSPROC3_SYMLINK = 10;
NFSPROC3_MKNOD = 11;
NFSPROC3_REMOVE = 12;
NFSPROC3_RMDIR = 13;
NFSPROC3_RENAME = 14;
NFSPROC3_LINK = 15;
NFSPROC3_READDIR = 16;
NFSPROC3_READDIRPLUS = 17;
NFSPROC3_FSSTAT = 18;
NFSPROC3_FSINFO = 19;
NFSPROC3_PATHCONF = 20;
NFSPROC3_COMMIT = 21;

##
# Generate an NFS request.
#
# @param creds Credential object, default an [rpc_auth_null].
# @param data Payload of the call message, default empty.
# @param gid Effective group ID, default 0.
# @param gids Supplemental group IDs, default none.
# @param host Host name, default the scanner's.
# @param proc Procedure the program is to execute.
# @param prog Program the payload is for.
# @param stamp Arbitrary ID, not explained by standard.
# @param udp Whether the packet will be sent over UDP.
# @param uid Effective user ID, default 0.
# @param verf Verifier object, default an [rpc_auth_null].
# @param ver Program version.
# @param xid Transaction identifier, default random.
#
# @return An NFS request in an RPC packet.
##
function nfs_req(creds, data, gid, gids, host, proc, prog, stamp, udp, uid, ver, verf, xid)
{
  if (isnull(gids))
    gids = make_list(0, 2, 3, 4, 5, 20, 31);

  if (isnull(ver))
    ver = 1;

  if (isnull(creds))
    creds = rpc_auth_unix(gid:gid, gids:gids, host:host, stamp:stamp, uid:uid);

  return rpc_packet(
    credentials : creds,
    data        : data,
    proc        : proc,
    prog        : prog,
    udp         : udp,
    verifier    : verf,
    vers        : ver,
    xid         : xid
  );
}

##
# Tell the mount daemon that we're done with the share.
#
# @param share Share we'd like to mount.
# @param soc Socket connected to mountd.
# @param udp Whether the socket is UDP.
# @param ver Version of the protocol.
#
# @return NULL on error, a file handle otherwise.
##
function nfs_mount(share, soc, udp, ver)
{
  local_var data, req, res;

  if (isnull(udp))
    udp = TRUE;

  # RFC 1094, Section A.5.2
  # RFC 1813, Section 5.2.1
  data = xdr_string(share);
  req = nfs_req(prog:MOUNT_PROGRAM, proc:MOUNTPROC_MNT, ver:ver, udp:udp, data:data);

  res = rpc_sendrecv(socket:soc, udp:udp, packet:req);
  if (isnull(res))
    return NULL;

  # Ensure that the RPC response had no errors.
  if (rpc_reply_stat() != RPC_REPLY_STAT_ACCEPTED || rpc_accept_stat() != RPC_ACCEPT_STAT_SUCCESS)
    return NULL;

  # Ensure the response is long enough to contain a MNT reply.
  if (strlen(res) < 36)
    return NULL;

  # Allow the XDR calls to operate on the payload.
  register_stream(res);

  # Check the NFS status.
  if (xdr_getdword() != 0)
    return NULL;

  # Get the file ID.
  return xdr_get_fix_opaque(32);
}

##
# List the contents of a directory.
#
# @param fid File handle.
# @param soc Socket connected to nfsd.
# @param udp Whether the socket is UDP.
# @param ver Version of the protocol.
#
# @return NULL on error, a list of file names otherwise.
##
function nfs_readdir(fid, soc, udp, ver)
{
  local_var data, file, files, flag, proc, req, res;

  if (isnull(udp))
    udp = TRUE;

  if (ver == 3)
    proc = NFSPROC3_READDIR;
  else
    proc = NFSPROC_READDIR;

  # RFC 1094, Section 2.2.17
  # RFC 1813, Section 3.3.16
  data =
    xdr_fix_opaque(fid, len:32) + # File ID
    xdr_long(0) +                 # NFS Cookie
    xdr_long(8192);               # Maximum response length
  req = nfs_req(prog:NFS_PROGRAM, proc:proc, udp:udp, ver:ver, data:data, host:"");

  res = rpc_sendrecv(socket:soc, udp:udp, packet:req);
  if (isnull(res))
    return NULL;

  # Ensure that the RPC response had no errors.
  if (rpc_reply_stat() != RPC_REPLY_STAT_ACCEPTED || rpc_accept_stat() != RPC_ACCEPT_STAT_SUCCESS)
    return NULL;

  # Ensure the response is long enough to contain a READDIR reply.
  if (strlen(res) < 8)
    return NULL;

  # Allow the XDR calls to operate on the payload.
  register_stream(res);

  # Check the NFS status.
  if (xdr_getdword() != 0)
    return NULL;

  files = make_list();

  while (TRUE)
  {
    # Parse value follows flag.
    flag = xdr_getdword();
    if (isnull(flag))
      return NULL;

    if (flag != 1)
      break;

    # Ignore file ID.
    if (isnull(xdr_getdword()))
      return NULL;

    # Parse file name.
    file = xdr_getstring();
    if (isnull(file))
      return NULL;

    # Ignore cookie.
    if (isnull(xdr_getdword()))
      return NULL;

    files = make_list(files, file);
  }

  return files;
}

##
# Get a handle for a file.
#
# @param fid File handle.
# @param file File to look up.
# @param soc Socket connected to nfsd.
# @param udp Whether the socket is UDP.
# @param ver Version of the protocol.
#
# @return NULL on error, new file's handle otherwise.
##
function nfs_lookup(fid, file, soc, udp, ver)
{
  local_var data, proc, req, res;

  if (isnull(udp))
    udp = TRUE;

  if (ver == 3)
    proc = NFSPROC3_LOOKUP;
  else
    proc = NFSPROC_LOOKUP;

  # RFC 1094, Section 2.2.5
  # RFC 1813, Section 3.3.3
  data =
    xdr_fix_opaque(fid, len:32) + # File ID
    xdr_string(file);             # File Name
  req = nfs_req(prog:NFS_PROGRAM, proc:proc, ver:ver, udp:udp, data:data);

  res = rpc_sendrecv(socket:soc, udp:udp, packet:req);
  if (isnull(res))
    return NULL;

  # Ensure that the RPC response had no errors.
  if (rpc_reply_stat() != RPC_REPLY_STAT_ACCEPTED || rpc_accept_stat() != RPC_ACCEPT_STAT_SUCCESS)
    return NULL;

  # Ensure the response is long enough to contain a LOOKUP reply.
  if (strlen(res) < 8)
    return NULL;

  # Allow the XDR calls to operate on the payload.
  register_stream(res);

  # Check the NFS status.
  if (xdr_getdword() != 0)
    return NULL;

  # Get the file ID.
  return xdr_get_fix_opaque(32);
}

##
# Read from a file handle.
#
# @param fid File handle.
# @param len Number of bytes to read.
# @param off Offset at which to begin reading.
# @param soc Socket connected to nfsd.
# @param udp Whether the socket is UDP.
# @param ver Version of the protocol.
#
# @return NULL on error, requested bytes from file otherwise.
##
function nfs_read(fid, len, off, soc, udp, ver)
{
  local_var data, proc, req, res;

  if (isnull(udp))
    udp = TRUE;

  if (ver == 3)
    proc = NFSPROC3_READ;
  else
    proc = NFSPROC_READ;

  # RFC 1094, Section 2.2.7
  # RFC 1813, Section 3.3.6
  data =
    xdr_fix_opaque(fid, len:32) + # File ID
    xdr_long(off) +               # Offset
    xdr_long(len) +               # Count
    xdr_long(0);                  # Total Count
  req = nfs_req(prog:NFS_PROGRAM, proc:proc, udp:udp, ver:ver, data:data);

  res = rpc_sendrecv(socket:soc, udp:udp, packet:req);
  if (isnull(res))
    return NULL;

  # Ensure that the RPC response had no errors.
  if (rpc_reply_stat() != RPC_REPLY_STAT_ACCEPTED || rpc_accept_stat() != RPC_ACCEPT_STAT_SUCCESS)
    return NULL;

  # Ensure the response is long enough to contain a MNT reply.
  if (strlen(res) < 36)
    return NULL;

  # Allow the XDR calls to operate on the payload.
  register_stream(res);

  # Check the NFS status.
  if (xdr_getdword() != 0)
    return NULL;

  # Get the file data.
  return xdr_get_fix_opaque(len);
}

##
# Tell the mount daemon that we're done with the share.
#
# @param share Share we're no longer using.
# @param soc Socket connected to mountd.
# @param udp Whether the socket is UDP.
# @param ver Version of the protocol.
##
function nfs_umount(share, soc, udp, ver)
{
  local_var data, req;

  if (isnull(udp))
    udp = TRUE;

  # RFC 1094, Section A.5.4
  # RFC 1813, Section 5.2.3
  data = xdr_string(share);
  req = nfs_req(prog:MOUNT_PROGRAM, proc:MOUNTPROC_UMNT, udp:udp, ver:ver, data:data);

  # Send the request, but ignore the response.
  rpc_sendrecv(socket:soc, udp:udp, packet:req);
}
