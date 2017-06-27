#TRUSTED 791da5e66aab23e67ca4acc90d1b10899f367a3a4384c407ce5dabf38335c4d0a5cdd84e7b936952b56a581e04e1a4020987d69913e93bc10a1cbb6ca9ddb451f9885d3614c357176442d5261a60203ab0e173b795a0e43b6b494df90fcbdb5a7482573b6d1d0173e25b9bf37c904903ef1be303a760d9ecb9af08bbb35f3bfef0ef1138428db8cd6ae092a18becd69582ba61559143784d206a4e4ab9dcb5cd204ac8e2711f721438ed791b17f0db8e29dfd08ef19c7adbb56e0b653279a972be261646987b55b64cde017cd84fe4f38816bab25043e41f579fe9b223d9050c229520cca82c53bc551e7e6bb9753579a2d213d7f34dd5d2cb11667376a6bb6994ab0152e95d1959f436a1d3a04c72c5d98aeb6ecfbfb625407d0201beef5353a400bc9afc51968d5d6f729a593e917157ea5035ad240e7e9435e1bee2097b7bfa759aed1399a22620764bbb11f1512468c6e88e26e5c54d251890ce80fdd1e0f9a09757dd84f4bca94c1044ac013e3efd50d5da44f63e5db0550bf1f0b0a992b51fa808252f7f583216336d0847b41bfac9631b2558dbf57071836dbaa2c6947c1754e22086732987cf252c1aee636dc14018fa176239ac71b114d04a3711345e53a6d80b2be9935645e7a834568d685a23f065a78e39a29967140428d2b6fa2de1fbb5ac6106ba35e7c3911f769c9c8f0452b0ca91ca6f0eb16aa7530c3851
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# sunrpc_func.inc
# Revision: 1.21
###

include ("byte_func.inc");

######################################################################
# External Data Representation Functions
######################################################################

###
# The current stream that the XDR functions parse.
###
global_var
  __rpc_stream,
  __rpc_stream_length,
  __rpc_stream_pos,
  __rpc_stream_error;

##
# Calculates the number of padding bytes needed to maintain alignment.
#
# @remark RFC 4506, Section 3.
#
# @return NULL on error, number of padding bytes otherwise.
##
function xdr_pad_len()
{
  local_var arg, len, pad, type;

  arg = _FCT_ANON_ARGS[0];

  type = typeof(arg);
  if (type == "data" || type == "string")
    len = strlen(arg);
  else if (type == "int" || type == "uint")
    len = arg;
  else
    return NULL;

  pad = len % 4;
  if (pad != 0)
    pad = 4 - pad;

  return pad;
}

##
# Pad a string appropriately.
#
# @remark RFC 4506, Section 3.
#
# @return NULL on error, padded string otherwise.
##
function xdr_pad(width)
{
  local_var len, str;

  str = _FCT_ANON_ARGS[0];
  if (isnull(str))
    str = "";

  len = strlen(str);

  if (isnull(width))
    width = len + xdr_pad_len(str);

  if (len > width)
    return NULL;

  return str + mkpad(width - len);
}

##
# Produces an XDR-format integer.
#
# @anonparam n Integer to convert to XDR format.
#
# @remark RFC 4506, Section 4.1.
#
# @return An XDR-format integer.
##
function xdr_long()
{
  return mkdword(_FCT_ANON_ARGS[0], order:BYTE_ORDER_BIG_ENDIAN);
}

##
# Reads a signed integer from the registered RPC stream.
#
# @remark RFC 4506, Section 4.1.
#
# @return NULL on error, signed integer otherwise.
##
function xdr_getdword()
{
  local_var d;

  if (__rpc_stream_pos + 4 > __rpc_stream_length)
  {
    __rpc_stream_error = TRUE;
    return NULL;
  }

  d = getdword(__rpc_stream, pos:__rpc_stream_pos, order:BYTE_ORDER_BIG_ENDIAN);
  __rpc_stream_pos += 4;

  return d;
}

##
# Produces an XDR-format string.
#
# @anonparam s String to convert to XDR format.
#
# @remark RFC 4506, Section 4.11.
#
# @return An XDR-format string.
##
function xdr_fix_opaque(len)
{
  return xdr_pad(_FCT_ANON_ARGS[0], width:len);
}

##
# Reads a string from the registered RPC stream.
#
# @remark RFC 4506, Section 4.11.
#
# @return NULL on error, string otherwise.
##
function xdr_get_fix_opaque()
{
  local_var data, len, pad;

  len = _FCT_ANON_ARGS[0];
  if (isnull(len))
    return NULL;

  if (__rpc_stream_pos + len > __rpc_stream_length)
  {
    __rpc_stream_error = TRUE;
    return NULL;
  }

  data = substr(__rpc_stream, __rpc_stream_pos, __rpc_stream_pos + len - 1);
  __rpc_stream_pos += len + xdr_pad_len(len);

  return data;
}

##
# Produces an XDR-format string.
#
# @anonparam s String to convert to XDR format.
#
# @remark RFC 4506, Section 4.11.
#
# @return An XDR-format string.
##
function xdr_var_opaque()
{
  local_var data;

  data = _FCT_ANON_ARGS[0];

  return xdr_long(strlen(data)) + xdr_pad(data);
}

##
# Reads a string from the registered RPC stream.
#
# @remark RFC 4506, Section 4.11.
#
# @return NULL on error, string otherwise.
##
function xdr_get_var_opaque()
{
  local_var data, len, pad;

  len = xdr_getdword();
  if (isnull(len))
    return NULL;

  return xdr_get_fix_opaque(len);
}

##
# Produces an XDR-format string.
#
# @anonparam s String to convert to XDR format.
#
# @remark RFC 4506, Section 4.11.
#
# @return An XDR-format string.
##
function xdr_string()
{
  local_var data, idx;

  data = _FCT_ANON_ARGS[0];

  idx = stridx(data, '\0');
  if (idx >= 0)
    data = substr(data, 0, idx - 1);

  return xdr_var_opaque(data);
}

##
# Reads a string from the registered RPC stream.
#
# @remark RFC 4506, Section 4.11.
#
# @return NULL on error, string otherwise.
##
function xdr_getstring()
{
  local_var data, idx;

  data = xdr_get_var_opaque();
  if (isnull(data))
    return NULL;

  idx = stridx(data, '\0');
  if (idx >= 0)
    data = substr(data, 0, idx - 1);

  return data;
}

######################################################################
# Remote Procedure Call Functions
######################################################################

###
# The result of [rpc_sendrecv].
###
global_var
  __rpc_reply_stat,
  __rpc_accept_stat;

###
# RFC 1057, Section A.1: Port Mapper Protocol Specification
###
global_var PMAP_PROGRAM;
PMAP_PROGRAM = 100000;

global_var
  PMAPPROC_NULL,
  PMAPPROC_SET,
  PMAPPROC_UNSET,
  PMAPPROC_GETPORT,
  PMAPPROC_DUMP,
  PMAPPROC_CALLIT;

PMAPPROC_NULL = 0;
PMAPPROC_SET = 1;
PMAPPROC_UNSET = 2;
PMAPPROC_GETPORT = 3;
PMAPPROC_DUMP = 4;
PMAPPROC_CALLIT = 5;

###
# RFC 1057, Section 7.2: Authentication
###
global_var
  RPC_AUTH_NULL,
  RPC_AUTH_UNIX,
  RPC_AUTH_SHORT,
  RPC_AUTH_DES;

RPC_AUTH_NULL = 0;
RPC_AUTH_UNIX = 1;
RPC_AUTH_SHORT = 2;
RPC_AUTH_DES = 3;

###
# RFC 1057, Section 8: The RPC Message Protocol
###
global_var
  RPC_MSG_TYPE_CALL,
  RPC_MSG_TYPE_REPLY;

RPC_MSG_TYPE_CALL = 0;
RPC_MSG_TYPE_REPLY = 1;

global_var
  RPC_REPLY_STAT_ACCEPTED,
  RPC_REPLY_STAT_DENIED;

RPC_REPLY_STAT_ACCEPTED = 0;
RPC_REPLY_STAT_DENIED = 1;

global_var
  RPC_ACCEPT_STAT_SUCCESS,
  RPC_ACCEPT_STAT_PROG_UNAVAIL,
  RPC_ACCEPT_STAT_PROG_MISMATCH,
  RPC_ACCEPT_STAT_PROC_UNAVAIL,
  RPC_ACCEPT_STAT_GARBAGE_ARGS;

RPC_ACCEPT_STAT_SUCCESS = 0;
RPC_ACCEPT_STAT_PROG_UNAVAIL = 1;
RPC_ACCEPT_STAT_PROG_MISMATCH = 2;
RPC_ACCEPT_STAT_PROC_UNAVAIL = 3;
RPC_ACCEPT_STAT_GARBAGE_ARGS = 4;

global_var
  RPC_REJECT_STAT_RPC_MISMATCH,
  RPC_REJECT_STAT_AUTH_ERROR;

RPC_REJECT_STAT_RPC_MISMATCH = 0;
RPC_REJECT_STAT_AUTH_ERROR = 1;

global_var
  RPC_AUTH_STAT_BADCRED,
  RPC_AUTH_STAT_REJECTEDCRED,
  RPC_AUTH_STAT_BADVERF,
  RPC_AUTH_STAT_REJECTEDVERF,
  RPC_AUTH_STAT_TOOWEAK;

RPC_AUTH_STAT_BADCRED = 1;
RPC_AUTH_STAT_REJECTEDCRED = 2;
RPC_AUTH_STAT_BADVERF = 3;
RPC_AUTH_STAT_REJECTEDVERF = 4;
RPC_AUTH_STAT_TOOWEAK = 5;

##
# Creates an RPC null authentication object.
#
# @remark RFC 1057, Section 9.1.
#
# @return An authentication object for [rpc_packet].
##
function rpc_auth_null()
{
  return make_list(RPC_AUTH_NULL, "");
}

##
# Creates an RPC unix authentication object.
#
# @param gid Effective group ID, default 0.
# @param gids Supplemental group IDs, default none.
# @param host Host name, default the scanner's.
# @param stamp Arbitrary ID, not explained by standard.
# @param uid Effective user ID, default 0.
#
# @remark RFC 1057, Section 9.2.
#
# @return An authentication object for [rpc_packet].
##
function rpc_auth_unix(gid, gids, host, stamp, uid)
{
  local_var auth, g;

  if (isnull(gid))
    gid = 0;

  if (isnull(gids))
    gids = make_list();

  if (isnull(host))
    host = this_host_name();

  if (isnull(stamp))
    stamp = rand();

  if (isnull(uid))
    uid = 0;

  auth =
    xdr_long(stamp) +
    xdr_string(host) +
    xdr_long(uid) +
    xdr_long(gid) +
    xdr_long(max_index(gids));

  foreach g (gids)
    auth += xdr_long(g);

  return make_list(RPC_AUTH_UNIX, auth);
}

##
# Creates an RPC call message.
#
# @param credentials A credential object, default an [rpc_auth_null].
# @param data Payload of the call message, default empty.
# @param proc Procedure the program is to execute.
# @param prog Program the payload is for.
# @param udp Whether the packet will be sent over UDP.
# @param verifier A verifier object, default an [rpc_auth_null].
# @param vers Program version.
# @param xid Transaction identifier, default random.
#
# @return The RPC call message.
##
function rpc_packet(credentials, data, proc, prog, udp, verifier, vers, xid)
{
  local_var pkt;

  if (isnull(credentials))
    credentials = rpc_auth_null();

  if (isnull(data))
    data = "";

  if (isnull(verifier))
    verifier = rpc_auth_null();

  if (isnull(xid))
    xid = rand();

  # RFC 1057, Section 8
  pkt =
    xdr_long(xid)               + # XID
    xdr_long(RPC_MSG_TYPE_CALL) + # Message Type (Call)
    xdr_long(2)                 + # RPC Version
    xdr_long(prog)              + # Program
    xdr_long(vers)              + # Program Version
    xdr_long(proc)              + # Procedure

    xdr_long(credentials[0]) +
    xdr_long(strlen(credentials[1])) +
    credentials[1] +

    xdr_long(verifier[0]) +
    xdr_long(strlen(verifier[1])) +
    verifier[1] +

    data;

  # RFC 1057, Section 10
  if (!udp)
  {
    pkt = xdr_long(strlen(pkt)) + pkt;
    pkt[0] = raw_string(0x80 | ord(pkt[0]));
  }

  return pkt;
}

##
# Receive an RPC message.
#
# RPC messages sent over TCP contain a Record Marker header that allows
# records to be fragmented. This function handles such fragmentation.
#
# @param length Maximum length of the record, default 8192 bytes.
# @param socket Socket to use.
# @param timeout Timeout to use during [recv].
# @param udp Whether socket is UDP.
#
# @return NULL on error, and a defragmented record otherwise.
##
function rpc_recv(length, packet, socket, timeout, udp)
{
  local_var fragment, last, len_fr, len_rec, len_rm, record, rm;

  if (isnull(length))
    length = 8192;

  if (udp)
    return recv(socket:socket, min:24, length:length, timeout:timeout);

  # RFC 1057, Section 10
  last = FALSE;
  len_rec = 0;
  while (!last)
  {
    # Limit the size of the record.
    if (len_rec > length)
      return NULL;

    # Receive the record mark.
    rm = recv(socket:socket, length:4, min:4, timeout:timeout);
    if (isnull(rm) || strlen(rm) != 4)
      return NULL;

    # Parse whether this is the last fragment.
    last = getbyte(rm) & 0x80;

    # Parse the fragment's length, removing the 'last' flag.
    rm[0] = raw_string(ord(rm[0]) & 0x7F);
    len_rm = getdword(rm, order:BYTE_ORDER_BIG_ENDIAN);
    if (len_rm <= 0 || len_rec + len_rm > length)
      return NULL;

    # Receive the remainder of the fragment.
    fragment = recv(socket:socket, min:len_rm, length:len_rm);
    if (!fragment)
      return NULL;

    # Confirm that we've received the entire fragment.
    len_fr = strlen(fragment);
    if (len_fr != len_rm)
      return NULL;

    len_rec += len_fr;
    record += fragment;
  }

  return record;
}

##
# Send an RPC call and recieve a reply.
#
# @param packet RPC call packet.
# @param socket Socket to use.
# @param timeout The timeout to use during [recv].
# @param udp Whether socket is UDP.
#
# @return NULL on error, the payload of the RPC message otherwise.
##
function rpc_sendrecv(packet, socket, timeout, udp)
{
  local_var len, res, xid1, xid2;

  # Default the statuses to success.
  __rpc_reply_stat = RPC_REPLY_STAT_ACCEPTED;
  __rpc_accept_stat = RPC_ACCEPT_STAT_SUCCESS;

  # Send the RPC packet.
  send(socket:socket, data:packet);

  # Recieve a record, ensuring it's at least the minimum length of a reply.
  res = rpc_recv(socket:socket, udp:udp, timeout:timeout);
  len = strlen(res);
  if (len < 24)
    return NULL;

  # Parse the XID from the request.
  if (udp)
    xid1 = getdword(packet, pos:0, order:BYTE_ORDER_BIG_ENDIAN);
  else
    xid1 = getdword(packet, pos:4, order:BYTE_ORDER_BIG_ENDIAN);

  # Parse the XID from the response.
  xid2 = getdword(res, pos:0);

  # Ensure the XIDs match, or else the response is for a request other
  # than the one we just sent.
  if (xid1 != xid2)
    return NULL;

  # Ensure the response is an RPC reply.
  if (getdword(res, pos:4, order:BYTE_ORDER_BIG_ENDIAN) != RPC_MSG_TYPE_REPLY)
    return NULL;

  # Parse reply state.
  __rpc_reply_stat = getdword(res, pos:8, order:BYTE_ORDER_BIG_ENDIAN);
  if (__rpc_reply_stat != RPC_REPLY_STAT_ACCEPTED)
    return NULL;

  # Parse accept state.
  __rpc_accept_stat = getdword(res, pos:20, order:BYTE_ORDER_BIG_ENDIAN);
  if (__rpc_accept_stat != RPC_ACCEPT_STAT_SUCCESS)
    return NULL;

  # Check if there is a payload.
  if (len == 24)
    return "";

  return substr(res, 24, len - 1);
}

##
# Register a stream for use by [xdr_getdword] and family.
#
# @param s String to register.
##
function register_stream(s)
{
  if (isnull(s))
    s = _FCT_ANON_ARGS[0];

  __rpc_stream = s;
  __rpc_stream_length = strlen(s);
  __rpc_stream_pos = 0;
  __rpc_stream_error = FALSE;
}

##
# Get the current stream error.
#
# @return The current stream error, if any.
##
function stream_error()
{
  return __rpc_stream_error;
}

##
# Get the current reply status.
#
# @return The reply status from the last parsed reply.
##
function rpc_reply_stat()
{
  return __rpc_reply_stat;
}

##
# Get the current accept status.
#
# @return The accept status from the last parsed reply.
##
function rpc_accept_stat()
{
  return __rpc_accept_stat;
}

##
# Find the RPC port for a given program and protocol.
#
# @param prog Program to be found.
# @param proto Protocol the program is using.
# @param socket Socket to communicate with portmapper.
# @param udp Whether the portmapper socket is UDP.
# @param vers What program version we want.
#
# @return NULL on error, a port number otherwise.
##
function rpc_getport(prog, proto, socket, udp, vers)
{
  local_var data, req, res;

  # Check required parameters.
  if (isnull(prog) || isnull(proto) || isnull(socket) || isnull(udp) || isnull(vers))
    return NULL;

  # RFC 1057, Section A.1
  data =
    xdr_long(prog) +
    xdr_long(vers) +
    xdr_long(proto) +
    xdr_long(0);

  req = rpc_packet(prog:PMAP_PROGRAM, vers:vers, proc:PMAPPROC_GETPORT, data:data, udp:udp);

  res = rpc_sendrecv(socket:socket, packet:req, udp:udp);
  if (isnull(res) || strlen(res) != 4)
    return NULL;

  return getdword(res, order:BYTE_ORDER_BIG_ENDIAN);
}

##
# Finds an RPC program's port.
#
# @param portmap Portmapper port, default from KB or 111.
# @param program Program to be found.
# @param protocol Protocol the program is using.
# @param udp Whether the portmapper socket is UDP.
# @param vers What program version we want, default 0.
#
# @return 0 on failure, and the program's port otherwise.
##
function get_rpc_port3(portmap, program, protocol, udp, vers)
{
  local_var kb, port, soc;

  if (isnull(vers))
    vers = 2;

  if (!isnull(portmap))
  {
    port = portmap;
  }
  else
  {
    if (udp)
      port = int(get_kb_item("rpc/portmap/UDP"));
    else
      port = int(get_kb_item("rpc/portmap/TCP"));

    if (!port)
      port = 111;
  }

  # Check if we already know there's no portmapper.
  kb = "/tmp/rpc/noportmap/" + port;
  if (get_kb_item(kb))
    return 0;

  if (udp)
    soc = open_sock_udp(port);
  else
    soc = open_sock_tcp(port);

  if (!soc)
    return 0;

  port = rpc_getport(socket:soc, prog:program, vers:vers, proto:protocol, udp:udp);
  close(soc);

  if (isnull(port))
  {
    # Remember that there's no portmapper.
    set_kb_item(name:kb, value:TRUE);
    return 0;
  }

  return port;
}

##
# Finds the RPC portmapper port.
#
# This function is intended to be a parameter-compatible replacement
# for the now defunct [get_rpc_port].
#
# @param portmap Portmapper port.
# @param program Program to be found.
# @param protocol Protocol the program is using.
# @param vers What program version we want.
#
# @return 0 on failure, and the portmapper port otherwise.
##
function get_rpc_port2(portmap, program, protocol, vers)
{
  local_var udp;

  udp = (int(get_kb_item("rpc/portmap/UDP")) > 0);

  return get_rpc_port3(program:program, protocol:protocol, portmap:portmap, vers:vers, udp:udp);
}

sunrpc_common_ports = make_array(
   111, "portmapper",   # Compulsory
   609, "pcnfsd",       # FreeBSD 6
   620, "sprayd",
   657, "nlockmgr",     # FreeBSD 8.2
   703, "ypbind",       # Linux
   706, "ypbind",       # Linux
   717, "status",       # FreeBSD 6
   737, "rstatd",
   743, "walld",
   747, "ypserv",       # FreeBSD6
   752, "rusersd",
   757, "nlockmgr",     # FreeBSD 6
   778, "rquotad",
   789, "rquotad",
   792, "rquotad",
   801, "ypserv",       # FreeBSD 6
   802, "nlockmgr",     # FreeBSD 8.2
   807, "mountd",       # FreeBSD 8.2
   834, "status",       # FreeBSD 6
   887, "rstatd",
   925, "status",       # FreeBSD 8.2
   950, "statd",
  1000, "nlockmgr",     # FreeBSD 6
  1012, "rstatd",
  1136, "nlockmgr",
  2049, "nfs",          # Very stable, on all OS
  2219, "mountd",
  4045, "nlockmgr",
 17185, "wdbrpc",
 32769, "filenet",
 32770, "portmapper",
 32771, "rusersd",
 32772, "status",
 32773, "rquotad",
 32774, "rusersd",
 32775, "status",
 32776, "sprayd",
 32777, "walld",
 32778, "rstatd",
 32779, "?",
 32780, "?",
 32786, "mountd",
 32787, "dmispd",
# Found on miscellaneous Linux/Solaris boxes
 33894, "mountd",
 34708, "mountd",
 36786, "mountd",
 37109, "nlockmgr",
 37387, "nlockmgr",
 37613, "nlockmgr",
 37760, "mountd",
 37814, "ypbind",
 38260, "status",
 38788, "status",
 39047, "status",
 40356, "status",
 40441, "mountd",
 41641, "status",
 41870, "nlockmgr",
 42522, "status",
 42552, "?",
 42566, "mountd",
 42596, "nlockmgr",
 45173, "status",
 45755, "status",
 47097, "status",
 47176, "mountd",
 47526, "mountd",
 48538, "mountd",
 48983, "nlockmgr",
 49284, "mountd",
 49269, "ypbind",
 49800, "nlockmgr",
 51297, "nlockmgr",
 51430, "sprayd",       # FreeBSD 6
 51638, "mountd",
 51712, "pcnfsd",       # FreeBSD 6
 52094, "status",
 54239, "nlockmgr",
 56221, "rquotad",      # FreeBSD 6
 56835, "mountd",
 57947, "nlockmgr",
 58622, "walld",        # FreeBSD 6
 58680, "mountd",
 58937, "nlockmgr",
 59633, "status",
 59685, "status",
 60015, "status",
 60602, "status",
 60615, "nlockmgr",
 60978, "mountd",
 63050, "rusersd",      # FreeBSD 6
 64201, "rquotad",
 64581, "rstatd"        # FreeBSD 6
);

sunrpc_prog_nb = make_array(
100000, "portmapper",
100001, "rstatd",
100002, "rusersd",
100003, "nfs",
100004, "ypserv",
100005, "mountd",
100007, "ypbind",
100008, "walld",
100009, "yppasswdd",
100010, "etherstatd",
100011, "rquotad",
100012, "sprayd",
100013, "3270_mapper",
100014, "rje_mapper",
100015, "selection_svc",
100016, "database_svc",
100017, "rexd",
100018, "alis",
100019, "sched",
100020, "llockmgr",
100021, "nlockmgr",
100022, "x25.inr",
100023, "statmon",
100024, "status",
100026, "bootparam",
100028, "ypupdated",
100029, "keyserv",
100033, "sunlink_mapper",
100037, "tfsd",
100038, "nsed",
100039, "nsemntd",
100043, "showfhd",
100055, "ioadmd",
100062, "NETlicense",
100065, "sunisamd",
100066, "debug_svc",
100068, "cmsd",
100069, "ypxfrd",
100071, "bugtraqd",
100078, "kerbd",
100101, "event",
100102, "logger",
100104, "sync",
100107, "hostperf",
100109, "activity",
100112, "hostmem",
100113, "sample",
100114, "x25",
100115, "ping",
100116, "rpcnfs",
100117, "hostif",
100118, "etherif",
100120, "iproutes",
100121, "layers",
100122, "snmp",
100123, "traffic",
100227, "nfs_acl",
100232, "sadmind",
100249, "snmpXdmid",
100300, "nisd",
100303, "nispasswd",
100233, "ufsd",
150001, "pcnfsd",
300019,  "amd",
300598, "dmispd",
391002, "sgi_fam",
545580417, "bwnfsd",
600100069, "fypxfrd",
805306368, "dmispd",
1073741824, "netbackup", # http://www.symantec.com/business/support/index?page=content&id=TECH71981
1289637086, "dtcm"
);
