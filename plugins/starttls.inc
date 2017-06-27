#TRUSTED 81724f3fed71b3b816c26eb40e6e424a8798977729081262388a1fbb8b3270cf1a0ee22ca8b7bec1fd000519b452dbb28e63a6567945261c05d5204921bf3520ec50ea7c39fd144c36d2ab46ad6a9917e0a4b9bc9cf9fabed8b2f27841c5e0a33581ebe3bc2ee957bb2413498b55a1e244afa2d664663fb996e4d695cba81cc6e6efb0dbec4812f27a846d6b35f775f90cd0963d5d4945f4c3131c96c2c4609e4802c19590d83681a8eea383fb6094780889c018b96429b4da8b6db3e5a0f13a1bf5e54be5abb09dcc2098235311dbdf7207d17a0dbf77997e47232a2d7c9f1fbd6c0b4215f63764703ccb6a631959da157aba61d081012f38cbf9a9a9630856ded7ee52ef46649c6e5ce05e20e7f302934e83b9e1f4bfe84729d88c04e06849b0f923856473ca4ea70409931841739de799172fdf4481a84bb09706b72d812478186db95ea44b635ba36773a529ef39cec67ec0760089f20e2f15a8fe63ac0604441efdd18b2ba0f5747d4e39d6828005d6b5e716dd70c629308ff120b8e2d064c83a84eecca6ff957161855c7306d18d654a9e781e055cedbd386949a7431b7f9ceef0f47e375874d87bf6f9ebed2ec61814c1c5623053160a13f3770f8121d50538d2877dcc0eee1a70581c19b21e37a822b7606ff698a14191506bfed1e35fe43a76bda9490e743fd85d35bf5c510cfc54038ca111531572282802130d52
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision 1.6
#

###
# Some applications implement custom protocols that support StartTLS.
# This library contains functions that will initiate StartTLS
# connections for such non-standard protocols. This will prevent
# having code occur in both a *_starttls.nasl plugin, and the
# open_sock_ssl() function in ssl_funcs.inc.
###

##
# Initiate a StartTLS connection.
#
# @param encaps The type of encapsulation to use
# @param socket The socket
#
# @remark If encaps is not specified, the socket that is returned will
#         not have the SSL negotiation performed.
#
# @return A connection in StartTLS mode.
##
function amqp_starttls(encaps, socket)
{
  local_var line, port, req, res, ver;

  # Sanity check parameters.
  if (!socket)
    return NULL;

  # We need to get the version from the KB, which is stored by port.
  if (!defined_func("get_peer_name"))
    return NULL;
  port = get_peer_name(socket);
  if (isnull(port) || isnull(port[1]))
    return NULL;
  port = port[1];

  ver = get_kb_item("amqp/" + port + "/protocol/version");
  if (isnull(ver))
    return NULL;
  ver = split(ver, sep:".", keep:FALSE);

  # Send command to request StartTLS negotiation.
  req = raw_string(
    "AMQP",      # Magic cookie
    2,           # Protocol ID
    int(ver[0]), # Major version number
    int(ver[1]), # Minor version number
    int(ver[2])  # Revision number
  );
  send(socket:socket, data:req);

  # Receive response, which should be identical to our request.
  res = recv(socket:socket, min:8, length:128);
  if (res != req)
    return NULL;

  # Check if the caller just wants the command sent, or if they want
  # the entire negotiation done.
  if (!encaps)
    return socket;

  if (!defined_func("socket_negotiate_ssl"))
    return NULL;

  return socket_negotiate_ssl(socket:socket, transport:encaps);
}

##
# Initiate a StartTLS connection.
#
# @param encaps The type of encapsulation to use
# @param socket The socket
#
# @remark If encaps is not specified, the socket that is returned will
#         not have the SSL negotiation performed.
#
# @remark A full library exists for this protocol, but only for NBINs.
#
# @remark This function spawns a child that MITMs the connection to
#         wrap/unwrap SSL messages during the handshake.
#
# @return A connection in StartTLS mode.
##
function mssql_starttls(encaps, socket)
{
  local_var enc, hdr, id, inner, len, middle, outer, pair, pos, ppid, req, rec, recs, res, state, type;

  # Sanity check parameters.
  if (!socket)
    return NULL;

  # Track the packet's ID, a sequence number.
  id = 0;

  # Create pre-login request.
  req = raw_string(
    18,                # Type (Pre-login message)
    0x01,              # Status (End of message)
    0x00, 0x2F,        # Length
    0x00, 0x00,        # SPID
    id++,              # PacketID
    0x00,              # Window

    0,                 # PL_OPTION_TOKEN (VERSION)
    0x00, 0x1A,        # Offset of field
    0x00, 0x06,        # Length of field

    1,                 # PL_OPTION_TOKEN (ENCRYPTION)
    0x00, 0x20,        # Offset of field
    0x00, 0x01,        # Length of field

    2,                 # PL_OPTION_TOKEN (INSTOPT)
    0x00, 0x21,        # Offset of field
    0x00, 0x01,        # Length of field

    3,                 # PL_OPTION_TOKEN (THREADID)
    0x00, 0x22,        # Offset of field
    0x00, 0x04,        # Length of field

    4,                 # PL_OPTION_TOKEN (MARS)
    0x00, 0x26,        # Offset of field
    0x00, 0x01,        # Length of field

    0xFF,              # PL_OPTION_TOKEN (TERMINATOR)

    16, 0, 0, 0, 0, 0, # VERSION
    0,                 # ENCRYPTION
    0,                 # INSTOPT
    "TNBL",            # THREADID
    0                  # MARS
  );

  # Send the pre-login request.
  send(socket:socket, data:req);

  # Receive response, ensuring it is large enough to hold the header
  # (8 bytes) and the terminator (1 byte).
  res = recv(socket:socket, min:9, length:1024);
  if (isnull(res) || strlen(res) < 9)
    return NULL;

  # Perform simple validation on the response.
  # Note: A fragmented packet will fail here.
  len = strlen(res);
  if (
    getbyte(blob:res, pos:0) != 4 ||
    getbyte(blob:res, pos:1) != 1 ||
    getword(blob:res, pos:2) != len
  ) return NULL;

  # Parse out the encryption field.
  pos = 8;
  enc = NULL;
  while (pos < len)
  {
    type = getbyte(blob:res, pos:pos);

    # Stop parsing if we hit the terminator.
    if (type == 0xFF)
      break;

    # Parse the ENCRYPTION field.
    if (type == 1)
    {
      if (pos + 1 >= len)
        break;
      pos = getword(blob:res, pos:pos + 1);

      if (pos >= len)
        break;
      enc = getbyte(blob:res, pos:pos);

      break;
    }

    pos += 5;
  }

  # Check if encryption is unsupported by the server.
  if (isnull(enc) || enc == 2)
    return NULL;

  # Remember who the parent is, so that the child can exit when the
  # parent does.
  ppid = getpid();

  # Set things up as follows:
  #   parent <-> inner|middle <-> child <-> outer
  pair = socketpair();
  inner = pair[0];
  middle = pair[1];
  outer = socket;

  # Fork, transferring ownership of the middle and outer sockets to
  # the child. If we're on the parent side of the fork, continue as
  # normal with the inner socket.
  if (fork(middle, outer) != 0)
  {
    # Check if the caller just wants the command sent, or if they want
    # the entire negotiation done.
    if (!encaps)
      return inner;

    if (!defined_func("socket_negotiate_ssl"))
      return NULL;

    return socket_negotiate_ssl(socket:inner, transport:encaps);
  }

  # According to the MS-TDS document, v20130118, section 3.3.5.3:
  #
  #   A TLS/SSL negotiation packet is a PRELOGIN (0x12) packet header
  #   encapsulated with TLS/SSL payload. The TDS server MUST exchange
  #   TLS/SSL negotiation packet with the client and reenter this
  #   state until the TLS/SSL negotiation is successfully completed.
  #
  # So what we're going to do is read in each SSL packet during the
  # handshake, mangling each, and then stop interfering once the
  # handshake is finished.
  #
  # Since both the parent and the child are waiting the same timeout
  # length, the child needs to know the sequence of a handshake,
  # otherwise it will wait one timeout period too long and the parent
  # will fail a recv() call. The indicators of switching state are:
  #
  #   middle:
  #     ClientHello      = send to outer immediately
  #     ChangeCipherSpec = send to outer after next record
  #
  #   outer:
  #     ChangeCipherSpec = send to middle after next record
  #
  # We can avoid more complex state logic on the outer socket because
  # the records are wrapped and we know the exact length, avoiding
  # needless waiting.

  state = make_array("middle", "start", "outer", "start");

  while (TRUE)
  {
    if (socket_pending(middle))
    {
      if (state["middle"] != "application-data")
      {
        # Collect all the SSL records available from the parent.
        recs = "";
        while (TRUE)
        {
          rec = recv_ssl(socket:middle);
          if (isnull(rec))
            break;
          recs += rec;

          if (state["middle"] == "start")
          {
            rec = ssl_find(
              blob:recs,
              "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
              "handshake_type", SSL3_HANDSHAKE_TYPE_CLIENT_HELLO
            );
            if (!isnull(rec))
            {
              state["middle"] = "after-hello";
              break;
            }
          }
          else if (state["middle"] == "after-hello")
          {
            rec = ssl_find(
              blob:rec, encrypted:FALSE,
              "content_type", SSL3_CONTENT_TYPE_CHANGECIPHERSPEC
            );
            if (!isnull(rec))
            {
              state["middle"] = "change-cipher-spec";
              break;
            }
          }
          else if (state["middle"] == "change-cipher-spec")
          {
            state["middle"] = "application-data";
            break;
          }
        }

        # Wrap data from middle -> outer.
        # Note: If OpenSSL ever sends 4088+ bytes, this will fail.
        len = 8 + strlen(recs);

        hdr = raw_string(
          18,          # Type (Pre-login message)
          0x01,        # Status (End of message)
          mkword(len), # Length
          0x00, 0x00,  # SPID
          id++,        # PacketID
          0x00         # Window
        );

        send(socket:outer, data:hdr + recs);
      }
      else
      {
        # Pass an SSL record through unmolested.
        rec = recv_ssl(socket:middle);
        if (isnull(rec))
          break;

        send(socket:outer, data:rec);
      }
    }

    if (socket_pending(outer))
    {
      if (state["outer"] != "application-data")
      {
        recs = "";
        while (TRUE)
        {
          # Read the TDS pre-login packet header.
          hdr = recv(socket:outer, length:8, min:8);
          if (isnull(hdr) || strlen(hdr) != 8 || getbyte(blob:hdr, pos:0) != 18)
            break;

          # Parse out the length of the packet body.
          len = getword(blob:hdr, pos:2) - 8;

          # Read the body of the TDS packet.
          res = recv(socket:outer, length:len, min:len);
          if (isnull(res) || strlen(res) != len)
          {
            recs = "";
            break;
          }
          recs += res;

          # Check if we've received all the fragments of the TDS message.
          if ((getbyte(blob:res, pos:1) & 0x1) == 1)
            break;
        }

        if (!recs)
          break;

        # Send all the unwrapped records to the parent.
        send(socket:middle, data:recs);

        # Transition our state.
        if (state["outer"] == "start")
        {
          recs = ssl_find(
            blob:rec, encrypted:FALSE,
            "content_type", SSL3_CONTENT_TYPE_CHANGECIPHERSPEC
          );
          if (!isnull(recs))
            state["outer"] = "change-cipher-spec";
        }
        else if (state["outer"] == "change-cipher-spec")
        {
          state["outer"] = "application-data";
        }
      }
      else
      {
        # Pass an SSL record through unmolested.
        rec = recv_ssl(socket:outer);
        if (isnull(rec))
          break;

        send(socket:middle, data:rec);
      }
    }

    # Check if the parent has exited.
    if (wait(pid:ppid, nonblock:TRUE) == -1)
      break;
  }

  # Clean up our sockets.
  close(middle);
  close(outer);

  # Exit silently.
  exit(0);
}

##
# Initiate a StartTLS connection.
#
# @param encaps The type of encapsulation to use
# @param socket The socket
#
# @remark If encaps is not specified, the socket that is returned will
#         not have the SSL negotiation performed.
#
# @return A connection in StartTLS mode.
##
function nut_starttls(encaps, socket)
{
  local_var line, res;

  # Sanity check parameters.
  if (!socket)
    return NULL;

  # Send command to request StartTLS negotiation.
  send(socket:socket, data:'STARTTLS\r\n');

  # Receive response.
  line = recv_line(socket:socket, length:1024);
  if (line !~ "^OK STARTTLS")
    return NULL;

  # Check if the caller just wants the command sent, or if they want
  # the entire negotiation done.
  if (!encaps)
    return socket;

  if (!defined_func("socket_negotiate_ssl"))
    return NULL;

  return socket_negotiate_ssl(socket:socket, transport:encaps);
}

##
# Prepares RDP server to accept a TLS connection
#
# @param socket Existing TCP connection to the RDP server.
# @param encaps SSL version to use when making an SSL/TLS connection
# @return a socket or NULL
# @remark
#   - If encaps is null and the function returns a socket, an SSL/TLS connection is not made, but
#     the server is the state to accept an SSL/TLS handshake.
#   - If encaps is not null and the function returns a socket, an SSL/TLS connection is made with the specified encapsulation.
#   - Negotiation-based SSL is supported in Windows Server 2003 and later.
#   - Direct (no negotiation) SSL is supported in later Windows OSes (ie Windows Server 2008)
#   - Caller should use encaps TLSv1 or later, as Windows RDP server doesn't support SSLv3
#
##
function rdp_starttls(encaps, socket)
{
  local_var data, len, req, res, type;

  req =
    # TPKT Header [T.123]
    '\x03' + # version number (always 0000 0011)
    '\x00' + # reserved (always 0)
    '\x00\x13' + # Length (including header) - big endian

    # Connection request TPDU
    '\x0e' +        # LI (length indicator)
    '\xe0' +        # CR (1110) + CDT (0000 = class 0 or 1)
    '\x00\x00' +    # DST REF (always 0)
    '\x00\x00' +    # SRC REF
    '\x00' +        # Class option (class 0)

    # RDP negotiation request
    '\x01' +            # RDP_NEG_REQ
    '\x00' +            # Flags (must be 0)
    '\x08\x00' +        # Length (must be 8) - little endian
    '\x03\x00\x00\x00'; # PROTOCOL_SSL | PROTOCOL_HYBRID

  send(socket:socket, data: req);

  res = recv(socket:socket, length:19, timeout:60);
  if(isnull(res)) return NULL;

  # Check length:
  # - Server supportting security protocol negotiation should return 19-byte response per  http://msdn.microsoft.com/en-us/library/cc240501.aspx, section 2.2.1.2
  # - Server (ie. on XP) not supportting negotiation returns a shorter response; these RDP servers are known to not support SSL
  if(strlen(res) != 19)
    return NULL;

  # Parse RDP_NEG_RSP or RDP_NEG_FAILURE
  type  = ord(res[11]);
  len   = ord(res[13]) | (ord(res[14]) << 8);
  data  = ord(res[15]) | (ord(res[16]) << 8) | (ord(res[17]) << 16) | (ord(res[18]) << 24); # selected proto for RDP_NEG_RSP or error code for RDP_NEG_FAILURE

  # RDP_NEG_RSP and RDP_NEG_FAILURE must be 8 bytes per protocol spec
  if(len != 8)
    return NULL;

  # Successful response (RDP_NEG_RSP)
  if(type == 2)
  {
    # We requested PROTOCOL_SSL|PROTOCOL_HYBRID, and should get either one of them
    if (data != 1 && data != 2)
      return NULL;

    # Establish a TLS connection if caller requests it
    if(! isnull(encaps) && encaps != ENCAPS_IP)
      return socket_negotiate_ssl(socket: socket, transport: encaps);
    else
      return socket;

  }
  # Error response (RDP_NEG_FAILURE)
  # possible causes:
  #   - RDP server configured to use only RDP legacy security
  #   - RDP server not configured/assigned a certificate for SSL
  else if(type == 3)
    return NULL;
  # Unknown response; unlikely to reach here
  else
    return NULL;
}

#----------------------------------------------------------------#
# Function    : ircd_starttls                                    #
# Description : Sends a STARTTLS command to an open socket.      #
# Inputs      : 'socket' => an open socket. (required)           #
#               'encaps' => if specified, complete the SSL       #
#                 handshake using the type of encapsulation      #
#                 specified by 'encaps'. (optional)              #
#               'exit_on_fail' => if specified, exit on a        #
#                 failure rather than returning NULL.            #
# Return      : The socket if the connection could be upgraded   #
#               or NULL otherwise.                               #
# Notes       : Attempting to complete the SSL handshake will    #
#               always result in a failure if the function       #
#               'socket_negotiate_ssl()' is not defined.         #
# Usage       : if (ircd_starttls(socket:soc, encaps:encaps))    #
#               {                                                #
#                 send(socket:soc, data:...                      #
#----------------------------------------------------------------#
function ircd_starttls(socket, encaps, exit_on_fail)
{
  local_var req, resp, s, ssl_socket;

  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  req = 'STARTTLS\r\n';
  send(socket:socket, data:req);

  resp = "";
  while(s = recv_line(socket:socket, length:2048))
  {
    s = chomp(s);
    # 670 is STARTTLS success
    # 691 is explicit STARTTLS failure/not supported
    # no response is STARTTLS not supported
    if(s =~ "^[^ ]+ (670|691) ")
    {
      resp = s;
      break;
    }
  }

  if (resp && resp =~ "^[^ ]+ 670 ")
  {
    if (encaps)
    {
      if (!defined_func("socket_negotiate_ssl"))
      {
        if (exit_on_fail) audit(AUDIT_FN_UNDEF, "socket_negotiate_ssl");
        else return NULL;
      }
      ssl_socket = socket_negotiate_ssl(socket:socket, transport:encaps);
      if (isnull(ssl_socket) && exit_on_fail) exit(1, "Failed to negotiate an SSL / TLS connection after sending a STARTTLS command.");
      else return ssl_socket;
    }
    return socket;
  }

  if (exit_on_fail) exit(1, "The IRC server did not send back a valid response to a STARTTLS command.");
  else return NULL;
}
