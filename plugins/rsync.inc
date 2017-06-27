#TRUSTED 1b87061df10e2cd052f9c93746dbe4ea32642ff572b9d465258d5e47f1f4596223e7b92a4d6314323e95a4d5945ea0db8bae55f4ec590084c53152ffb00cdd2d025b59937673634cd9de2c34dd0b3fba9c80d656c56a50048ba3f587c30c47abd1a6a42c385b398f844149804336544417fc92f7dbd57ed4e37ce95c8442dea626ff8bf455e83aff3e86625bde35fb4b3b08a8b5f5ac7a69561e4caa037fac86fddd9e00fa98ebd505835228d0dac6424293b13104a82f6c4b153b7b089300a5bced6f5d49acea7d9e274cc048e7b0dc2a6ff46cfc677579423c5166f38b346c2da1d603b95fd9acbee07fe249266d9a2ebb89131a23c654dd2ced8791f4dd94aca0013711f1640e3af1dd90ce6c41abe530643fcda30d03290b81a0b0392efb9a5cf5ed747add6f8063e228b60dd6fddb4aaad83c5af8dac5181c5fabbe8d496a144e3f8b8ae2936573bb4f56f956b650aa386c60443fbd24356f1f2adbe8845289379b9e18af4a342f4fc8d7c2ae5f9e8c64abc1e9c44810162f7b1b9b2f6808b5ed30d46488f9995586f7ec039c6fb6711d05507d561d9fa2f8ddf976b10cdfe76cd85480f810505936f0661a30cdea336674b46648f2c1f5a9f78fe2fb08f331c6b6b5858aea782280c5304fdc72d060e59084aba449e99b8d328e9b768084ccb9daf836c653ece7bbf1383e6723781249690a95a218b1377afeffae16fa
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# rsync.inc
#
# Revision: 1.2
#
# @include audit.inc
# @include global_settings.inc
# @include byte_func.inc
# @include misc_func.inc
# @include string.inc
###

##
# Initiate connection to an Rsync daemon.
#
# @param int port OPTIONAL defaults to 873
# @param int socket OPTIONAL existing socket to use instead of port
# @param int exit_if_not_found OPTIONAL defaults to FALSE, exits
#            if opening the socket fails.
#
# @return int socket if successful
#             NULL if failure
##
function rsync_init(port, exit_if_fail, socket)
{
  local_var soc, r, peer_name;

  if (isnull(exit_if_fail)) exit_if_fail = FALSE;

  # validate the socket by attempting to get its port
  peer_name = NULL;
  if (!isnull(socket) && socket != 0) peer_name = get_peer_name(socket);

  if (!isnull(peer_name) && !isnull(peer_name[1]))
  {
    # existing socket to use instead of port
    soc = socket;

    # get the port it is using
    port = peer_name[1];
  }
  else
  {
    # open new socket
    if (isnull(port)) port = 873;

    soc = open_sock_tcp(port);
    if (!soc)
    {
      if (exit_if_fail) audit(AUDIT_SOCK_FAIL, port);
      return NULL;
    }
  }

  r = recv_line(socket:soc, length:4096);
  if (isnull(r))
  {
    close(soc);
    if (exit_if_fail) audit(AUDIT_NOT_LISTEN, "Rsync Daemon", port);
    return NULL;
  }

  # check for motd
  r = recv_line(socket:soc, length:4096);

  # protocol 29.0 is way simpler than 30.0
  send(socket:soc, data:'@RSYNCD: 29.0\n');

  return soc;
}

##
# Obtain a list of modules available from an Rsync Daemon.
#
# @param int socket
#
# @remark rsync_init() must be called before this.
#
# @return list of strings that contain module name and comment
#         separated by a null char.
#         NULL if failure (bad socket)
##
function rsync_list_modules(socket)
{
  local_var modules, i, r, m, name, comment;

  if (isnull(socket))
  {
    err_print("rsync_list_modules(): missing required argument 'socket'.");
    return NULL;
  }

  send(socket:socket, data:'#list\r\n');

  modules = make_list();

  for(i=0; i<255; i++)
  {
    r = recv_line(socket:socket, length:4096);
    if(!r || "@RSYNC" >< r)
      break;
    m = split(r, sep:" ", keep:FALSE);
    name = m[0];
    # rsync inserts 15 spaces between the module name and the comment
    comment = chomp(string_reverse(chomp(string_reverse(r - name))));
    modules = make_list(modules, name + '\x00' + comment);
  }

  return modules;
}

##
# Tests if PUTing a file on a module works.
#
# @param int    socket
# @param string module name of the module to connect to
# @param string file_name the name of the file to attempt to write (including path, if any)
#
# @return int TRUE if this module is writable
#             FALSE if this module is not writable
#             NULL if an error occurs
##
function rsync_test_put_file(socket, module, file_name)
{
  local_var r, file_len;

  if (isnull(socket))
  {
    err_print("rsync_test_put_file(): missing required argument 'socket'.");
    return NULL;
  }

  if (isnull(module) || (typeof(module) != "data" && typeof(module) != "string"))
  {
    err_print("rsync_test_put_file(): invalid or missing required argument 'module'.");
    return NULL;
  }

  if (isnull(file_name) || (typeof(file_name) != "data" && typeof(file_name) != "string"))
  {
    err_print("rsync_test_put_file(): invalid or missing required argument 'file_name'.");
    return NULL;
  }

  push_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

  send(socket:socket, data:module + '\n');

  r = recv_line(socket:socket, length:4096);
  if("@RSYNCD: OK" >!< r)
  {
    pop_byte_order();
    return NULL;
  }

  send(socket:socket, data:'--server\n.\n' + module + '/' + file_name + '\n\n');
  r = recv(socket:socket, length:4096);

  file_len = 42; # arbitrary

  # this packet tells the rsync daemon that we are about to PUT a file
  send(socket:socket, data:
    '\x18' + # put command ?
    mkbyte(strlen(file_name)) +
    file_name +
    mkdword(file_len) +
    hex2raw(s:'e2b63654') + # crc based on adler32
    hex2raw(s:'b481') +
    hex2raw(s:'00000000000000')
  );

  # if the module is read-only, the server will disconnect us here
  r = recv(socket:socket, length:4096);

  pop_byte_order();

  if (!isnull(r))
  {
    # writeable!
    return TRUE;
  }

  return FALSE;
}

##
# Retrieve a file from an Rsync daemon
#
# @param int    socket
# @param string module name of the module to connect to
# @param string file_name the name of the file to retrieve (including path, if any)
#
# @return string contents of the file if successful
#                NULL if failure
##
function rsync_get_file(socket, module, file_name)
{
  local_var r, str1, pos_len, pos_file, pos_file_end, file_len, file_contents;

  if (isnull(socket))
  {
    err_print("rsync_get_file(): missing required argument 'socket'.");
    return NULL;
  }

  if (isnull(module) || (typeof(module) != "data"  && typeof(module) != "string"))
  {
    err_print("rsync_get_file(): invalid or missing required argument 'module'.");
    return NULL;
  }

  if (isnull(file_name) || (typeof(file_name) != "data"  && typeof(file_name) != "string"))
  {
    err_print("rsync_get_file(): invalid or missing required argument 'file_name'.");
    return NULL;
  }

  push_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

  send(socket:socket, data:module + '\n');

  r = recv_line(socket:socket, length:4096);
  if("@RSYNCD: OK" >!< r)
  {
    pop_byte_order();
    return NULL;
  }

  send(socket:socket, data:'--server\n--sender\n-L\n.\n' + module + '/' + file_name + '\n\n');
  r = recv(socket:socket, length:4096);

  # an adler32 based crc of the local file for diffing purposes
  # sending all zeros tells the daemon we don't have the file yet
  send(socket:socket, data:'\x00\x00\x00\x00');
  r = recv(socket:socket, length:4096);
  if (isnull(r))
  {
    pop_byte_order();
    return NULL;
  }

  str1 = hex2raw(s:'0000000000a000000000000000000000000000000000');
  send(socket:socket, data:str1);
  r = recv(socket:socket, length:65535);

  pos_len = strlen(str1) + 4;
  pos_file = strlen(str1) + 8;

  if (isnull(r) || strlen(r) < (pos_file + 4))
  {
    pop_byte_order();
    return NULL;
  }

  file_len = getdword(blob:r, pos:pos_len);

  pos_file_end = pos_file + file_len - 1;

  if (strlen(r) < pos_file_end)
  {
    pop_byte_order();
    return NULL;
  }

  file_contents = substr(r, pos_file, pos_file_end);

  pop_byte_order();

  return file_contents;
}

#----------------------------------------------------------------#
# Function    : rsync_starttls                                    #
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
# Usage       : if (rsync_starttls(socket:soc, encaps:encaps))    #
#               {                                                #
#                 send(socket:soc, data:...                      #
#----------------------------------------------------------------#
function rsync_starttls(socket, encaps, exit_on_fail)
{
  local_var req, resp, ssl_socket;

  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  req = '#starttls\r\n';
  send(socket:socket, data:req);

  resp = recv_line(socket:socket, length:2048);

  if (resp && resp =~ "^@RSYNCD: starttls")
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

  if (exit_on_fail) exit(1, "The rsync server did not send back a valid response to a STARTTLS command.");
  else return NULL;
}
