#TRUSTED 0838adf830995a67a5f74e3f0af37efb4e33bd239a512c5543d8898fee59dfeb4b19e2d39b01fad5e38fa8074fa2dd87f2093ac740588453645a1cb193840570a246792cfc974303200c702c196a4cf0e2566875afc717653d3d56f2bdab71db0c01ffde01206cd2e5f1dc2f59d9b9af6f4b8d028dc911190fde4e9b23c739dd94d6aa5f4a4cdafc6727ae1701ea49227e376f23f3f7667f69c8e2271f3eca848a61cb60d9cf624e1b631316704328525decd2bd97d2718a6b8b2dcc11d13818b3781aa6f55eed540e77974b8797e0ef94e369353682593e995a3a33a8fb9fc31ac97f6f8f225c409c75d523c548d8caa590efde5fef1233971e10256adb5ac7b80305e706bbfebe0e073ed51f0a70c2de044e9c914bdbd80044f82dd7a7874077fcecda04d12fc29c381190f6692fc8306afd6d4ccf37cbe2852a02a1291c9d345a2dd19db1497c2b61925119b013f8b7e0503219d1149d1e832ef9ccb0ecbe648f671d19193f7c2c04bd53058d74f72b08a632250a50dfeebbd9d6a3c0e7d86261decd85da958d421a0f8a705d1bf31220ddee3fd48d37a1ba4a7c27df31233f2be29f29d78d86c325248022f3175800768e262d25add7363aaa0cbe0e5e8f945de30de5baa8acdd7f9ddd28e77d637cdc3430f9fca192d0c183c7f00931e32b52c10bd104bd19badf3fad0a3fbede06ce334d35e1b260373aa8a680ee712a
#------------------------------------------------------------------------------
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# ssh_fxp_func.inc
# Revision: 1.2
#
# @include byte_func.inc
# @include ssh_func.inc


##
# Constants used for FXP requests.
# 
# @remark SFTP spec: http://tools.ietf.org/html/draft-ietf-secsh-filexfer-00
# @remark SFTP packet types
##
SSH_FXP_INIT           =   1;
SSH_FXP_VERSION        =   2;
SSH_FXP_OPEN           =   3;
SSH_FXP_CLOSE          =   4;
SSH_FXP_READ           =   5;
SSH_FXP_WRITE          =   6;
SSH_FXP_LSTAT          =   7;
SSH_FXP_FSTAT          =   8;
SSH_FXP_SETSTAT        =   9;
SSH_FXP_FSETSTAT       =  10;
SSH_FXP_OPENDIR        =  11;
SSH_FXP_READDIR        =  12;
SSH_FXP_REMOVE         =  13;
SSH_FXP_MKDIR          =  14;
SSH_FXP_RMDIR          =  15;
SSH_FXP_REALPATH       =  16;
SSH_FXP_STAT           =  17;
SSH_FXP_RENAME         =  18;
SSH_FXP_STATUS         = 101;
SSH_FXP_HANDLE         = 102;
SSH_FXP_DATA           = 103;
SSH_FXP_NAME           = 104;
SSH_FXP_ATTRS          = 105;
SSH_FXP_EXTENDED       = 200;
SSH_FXP_EXTENDED_REPLY = 201;

##
# Error codes.
##
SSH_FX_OK                          =  0;
SSH_FX_EOF                         =  1;
SSH_FX_NO_SUCH_FILE                =  2;
SSH_FX_PERMISSION_DENIED           =  3;
SSH_FX_FAILURE                     =  4;
SSH_FX_BAD_MESSAGE                 =  5;
SSH_FX_NO_CONNECTION               =  6;
SSH_FX_CONNECTION_LOST             =  7;
SSH_FX_OP_UNSUPPORTED              =  8;
SSH_FX_INVALID_HANDLE              =  9;
SSH_FX_NO_SUCH_PATH                = 10;
SSH_FX_FILE_ALREADY_EXISTS         = 11;
SSH_FX_WRITE_PROTECT               = 12;
SSH_FX_NO_MEDIA                    = 13;
SSH_FX_NO_SPACE_ON_FILESYSTEM      = 14;
SSH_FX_QUOTA_EXCEEDED              = 15;
SSH_FX_UNKNOWN_PRINCIPAL           = 16;
SSH_FX_LOCK_CONFLICT               = 17;
SSH_FX_DIR_NOT_EMPTY               = 18;
SSH_FX_NOT_A_DIRECTORY             = 19;
SSH_FX_INVALID_FILENAME            = 20;
SSH_FX_LINK_LOOP                   = 21;
SSH_FX_CANNOT_DELETE               = 22;
SSH_FX_INVALID_PARAMETER           = 23;
SSH_FX_FILE_IS_A_DIRECTORY         = 24;
SSH_FX_BYTE_RANGE_LOCK_CONFLICT    = 25;
SSH_FX_BYTE_RANGE_LOCK_REFUSED     = 26;
SSH_FX_DELETE_PENDING              = 27;
SSH_FX_FILE_CORRUPT                = 28;
SSH_FX_OWNER_INVALID               = 29;
SSH_FX_GROUP_INVALID               = 30;
SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK = 31;

##
# SFTP file attribute flag bits
##
SSH_FILEXFER_ATTR_SIZE        = 0x00000001;
SSH_FILEXFER_ATTR_UIDGID      = 0x00000002;
SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004;
SSH_FILEXFER_ATTR_ACMODTIME   = 0x00000008;
SSH_FILEXFER_ATTR_EXTENDED    = 0x80000000;


##
# Request id used in FXP requests.
##
global_var _request_id;
_request_id = rand() % 1000;

##
# Used for storing an error message.
##
global_var _ssh_fxp_error;
_ssh_fxp_error = "";

##
# Version of the protocol supported.
##
global_var _ssh_fxp_protocol_version;
_ssh_fxp_protocol_version = 3;

##
# Assorted constants used both here and in ssh_func.inc.
##
global_var _ssh_protocol, _ssh_socket;


##
# Saves an error message.
#
# @param msg message.
##
function ssh_fxp_set_error(msg)
{
 _ssh_fxp_error = msg;
}

##
# Gets the current error message.
#
# @return previously saved message.
##
function ssh_fxp_get_error()
{
 return _ssh_fxp_error;
}

##
# Gets the current protocol version.
#
# @return previously negotiated protocol version
##
function ssh_fxp_get_protocol_version()
{
 return _ssh_fxp_protocol_version;
}


##
# Sends a FXP payload over an already-established SSH channel,
# wrapping it in FXP and SSH2_MSG_CHANNEL_DATA headers
#
# @param type FXP packet type
# @param data FXP data
#
# @return whatever send_ssh_packet() returns (don't know if that functions returns anything)
##
function ssh_fxp_send_packet(type, data)
{
  local_var payload;

  # The FXP payload
  if (type == SSH_FXP_INIT || type == SSH_FXP_VERSION)
  {
    payload = raw_int8(i:type) + data;
  }
  else
  {
    payload = raw_int8(i:type) + raw_int32(i:_request_id++) + data;
  }

  # add SSH_MSG_CHANNEL_DATA and FXP headers
  payload = 
    raw_int32(i:remote_channel) +
    raw_int32(i:strlen(payload)+4) +
    raw_int32(i:strlen(payload)) +
    payload;

  return send_ssh_packet(payload:payload, code:raw_int8(i:SSH2_MSG_CHANNEL_DATA));
}


##
# Receives a FXP payload over an already-established SSH channel
# and parses it.
#
# @param exit_on_fail if TRUE, exits in lieu of returning NULL. FALSE by default
#
# @return parsed data - an array with keys 'receipient_channel', 'type', and 'data', NULL if there was a problem.
##
function ssh_fxp_recv_packet(exit_on_fail)
{
  local_var code, len, payload, res, val;

  payload = recv_ssh_packet();
  code = ord(payload[0]);

  # Ignore packets that we don't care about
  while (code == 93 || code == 95 || code  == 98)
  {
    if (code == 93)
    {
      payload = getstring(buffer:payload, pos:5);
      val = update_window_size(size:strlen(payload));
      if (val != 0) break;
    }
    else if (code == 95)
    {
      payload = getstring(buffer:payload, pos:9);
      val = update_window_size(size:strlen(payload));
      if (val != 0) break;
    }
    payload = recv_ssh_packet();
    code = ord(payload[0]);
  }

  if (strlen(payload) == 1 && code == 0)
  {
    ssh_fxp_set_error(msg:"The SSH service did not respond.");
    if (exit_on_fail) exit(1, ssh_fxp_get_error());
    else return NULL;
  }
  if (code != SSH2_MSG_CHANNEL_DATA)
  {
    ssh_fxp_set_error(msg:"The FXP response packet starts with "+code+", not "+SSH2_MSG_CHANNEL_DATA+" (SSH2_MSG_CHANNEL_DATA).");
    if (exit_on_fail) exit(1, ssh_fxp_get_error());
    else return NULL;
  }
  if (strlen(payload) < 14 + 4)
  {
    ssh_fxp_set_error(msg:"The FXP response packet is too short.");
    if (exit_on_fail) exit(1, ssh_fxp_get_error());
    else return NULL;
  }

  res = make_array();
  res['receipient_channel'] = ntol(buffer:payload, begin:1);
  len = ntol(buffer:payload, begin:9) - 1;  # length of FXP response payload (-1 for the type field)
  res['type'] = ord(payload[13]);
  res['data'] = substr(payload, 14);

  if (len != strlen(res['data']))
  {
    ssh_fxp_set_error(msg:"Length of the FXP response differs from expected length.");
    if (exit_on_fail) exit(1, ssh_fxp_get_error());
    else return NULL;
  }

  return res;
}


##
# Opens a connection and starts the sftp subsystem.
#
# @param cert Certificate with public key, signed by CA key.
# @param host Hostname for kerberos.
# @param port Port on which SSH server listens.
# @param password Password to attempt to log in with.
# @param passphrase Passphrase to decrypt private key.
# @param priv Private key, possibly encrypted.
# @param pub Public key or certificate.
# @param realm Kerberos realm
# @param user Username to attempt to log in with.
# @param want_reply Used to set 'want_reply'.
# @param version is the FXP protocol version to support.
#
# @return TRUE if successful, FALSE otherwise.
#
# @remark If there was a failure to open an FXP connection, the SSH connection itself is closed.
##
function ssh_fxp_open_connection(cert, host, port, login, password, passphrase, priv, pub, realm, want_reply, version)
{
  local_var payload, rc, res, val;

  _ssh_socket = open_sock_tcp(port);
  if (!_ssh_socket)
  {
    ssh_fxp_set_error(msg:"Failed to open a socket on port "+port+".");
    return FALSE;
  }

  rc = ssh_login(
    login      : login,
    password   : password,
    pub        : pub,
    priv       : priv,
    passphrase : passphrase,
    realm      : realm,
    host       : host,
    cert       : cert
  );
  if (rc != 0)
  {
    ssh_close_connection();
    ssh_fxp_set_error(msg:"Failed to authenticate.");
    return FALSE;
  }

  if (_ssh_protocol == 1)
  {
    ssh_close_connection();
    ssh_fxp_set_error(msg:"The SSH service supports SSH 1.");
    return FALSE;
  }
  
  if (want_reply) set_ssh_want_reply(TRUE);

  # Open a channel.
  rc = ssh_open_channel();
  if (rc != 0)
  {
    ssh_close_connection();
    ssh_fxp_set_error(msg:"Failed to open a channel.");
    return FALSE;
  }

  # Check if the subsystem is supported.
  rc = ssh_request_subsystem(subsystem:"sftp", want_reply:want_reply);
  if (!rc) 
  {
    ssh_close_connection();
    ssh_fxp_set_error(msg:"The sftp subsystem is not supported.");
    return FALSE;
  }
  
  # Initialize the connection.
  if (!isnull(version)) _ssh_fxp_protocol_version = version;

  ssh_fxp_send_packet(type:SSH_FXP_INIT, data:raw_int32(_ssh_fxp_protocol_version));
  res = ssh_fxp_recv_packet(exit_on_fail:TRUE);
  if (res['type'] != SSH_FXP_VERSION)
  {
    ssh_fxp_set_error(msg:"Received packet type was " + ord(res['type']) + ", not SSH_FXP_VERSION (" + SSH_FXP_VERSION + ")");
    return FALSE;
  }

  val = ntol(buffer:res['data'], begin:0);
  if (val != _ssh_fxp_protocol_version)
  {
    ssh_fxp_set_error(msg:"The remote does not support version " + _ssh_fxp_protocol_version + " of the SFTP protocol; it supports " + val + ".");
    return FALSE;
  }

  return TRUE;
}

##
# Closes an FXP connection.
##
function ssh_fxp_close_connection()
{
  ssh_close_connection();
}


##
# Gets directory listing
#
# @remark This function only supports SFTP protocol version 3 currently.
#
# @remark Note that the caller is responsible for opening and closing the SSH connection.
#
# @param dir Directory to list.
# @param max_files Maximum number of files to include in the listing.
#
# @return array with file names and attributes, or NULL if there was a problem.
##
function ssh_fxp_get_listing(dir, max_files)
{
  local_var dh, payload, res, val;
  local_var attr_flags, extended_count, extended_data_len, extended_type_len, i, j, listing, n, pos;

  if (ssh_fxp_get_protocol_version() != 3)  
  {
    ssh_fxp_set_error(msg:"The remote service does not support version 3 of the SFTP protocol.");
    return NULL;
  }

  ssh_fxp_send_packet(type:SSH_FXP_OPENDIR, data:putstring(buffer:dir));
  res = ssh_fxp_recv_packet(exit_on_fail:TRUE);
  if (res['type'] == SSH_FXP_STATUS)
  {
    local_var err_msg;
    err_msg = "Failed to open the directory";

    if (strlen(res['data']))
    {
      val = ntol(buffer:res['data'], begin:5);
      payload = getstring(buffer:res['data'], pos:8);
      if (strlen(payload) > 0) err_msg += " - " + payload;
      else if (val == 2) err_msg += " - no such file";
      else if (val == 3) err_msg += " - permission denied";
      else if (val == 4) err_msg += " - failure";
      else if (val == 5) err_msg += " - bad message";
      else if (val == 6) err_msg += " - no connection";
      else if (val == 7) err_msg += " - connection lost";
      else if (val == 8) err_msg += " - operation unsupported";
    }
    ssh_fxp_set_error(msg:err_msg+".");
    return NULL;
  }
  if (res['type'] != SSH_FXP_HANDLE)
  {
    ssh_fxp_set_error(msg:"Received FXP packet type was SSH_FXP_HANDLE (" + SSH_FXP_HANDLE + "); it was " + res['type'] + ".");
    return NULL;
  }
  dh = getstring(buffer:res['data'], pos:4);

  listing = make_array();
  listing['files'] = make_array();

  i = 0;
  while (TRUE)
  {
    ssh_fxp_send_packet(type:SSH_FXP_READDIR, data:putstring(buffer:dh));
    res = ssh_fxp_recv_packet(exit_on_fail:TRUE);
    if (res['type'] == SSH_FXP_STATUS) break;
    else if (res['type'] != SSH_FXP_NAME)
    {
      ssh_fxp_set_error(msg:"Received FXP packet type was SSH_FXP_NAME (" + SSH_FXP_NAME + "); it was " + res['type'] + ".");
      return NULL;
    }
  
    pos = 0;
    # request_id = ntol(buffer:res['data'], begin:pos);
  
    pos += 4;
    n = ntol(buffer:res['data'], begin:pos);
  
    pos += 4;
    for (; i<n; i++)
    {
      local_var filename, longname;

      if (i == max_files)
      {
        listing['truncated'] = TRUE;
        break;
      }

      filename = getstring(buffer:res['data'], pos:pos);
      pos += 4 + strlen(filename);
      longname = getstring(buffer:res['data'], pos:pos);
      pos += 4 + strlen(longname);
      if (strlen(longname) == 0) longname = filename;
      listing['files'][filename] = longname;

      # nb: for now, the code in this block only is used to read
      #     over file attributes. At some point, we could parse those
      #     and construct our own 
      attr_flags = ntol(buffer:res['data'], begin:pos);
      pos += 4;

      if (attr_flags & SSH_FILEXFER_ATTR_SIZE)
      {
        # size (uint64)
        pos += 8;
      }
      if (attr_flags & SSH_FILEXFER_ATTR_UIDGID)
      {
        # uid & gid (uint32 & uint32)
        pos += 4 + 4;
      }
      if (attr_flags & SSH_FILEXFER_ATTR_PERMISSIONS)
      {
        # permissions (uint32)
        pos += 4;
      }
      if (attr_flags & SSH_FILEXFER_ATTR_ACMODTIME)
      {
        # atime & mtime (uint32 / uint32)
        pos += 4 + 4;
      }
      if (attr_flags & SSH_FILEXFER_ATTR_EXTENDED)
      {
        # extended_count (uint32)
        extended_count = ntol(buffer:res['data'], begin:pos);
        pos += 4;

        for (j=0; j<extended_count; j++)
        {
          extended_type_len = ntol(buffer:res['data'], begin:pos);
          pos += 4 + extended_type_len;
          extended_data_len = ntol(buffer:res['data'], begin:pos); 
          pos += 4 + extended_data_len;
        }
      }
    }
  }
  
  # Close the handle but don't worry about the response.
  ssh_fxp_send_packet(type:SSH_FXP_CLOSE, data:putstring(buffer:dh));

  return listing;
}
