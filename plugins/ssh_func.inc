#TRUSTED 2161155dad7a3b1abd2bd0045c392020f62b5b1814d5c403c8ce25ce7f9178fb450eefbda87563f1cbc721ec6c79e08648ff9e1034a3748529aaee79c6d841ded6a5634d72c81ec32e788e29bb7c198e179b183ac1dcd7a4058c8b4c803ed80228336f3a88f317c96720f52ec481c1bfba366328f77abed3a7c32f55483031089dc5d7cf64190656de8e22bd1f523f004bbcd4922486fd59d9e808955d69de4a99e6eb3971d422cd19ff2073c2312611e1a0080e978de0c1cb5c4f12d7227ea042591eb9d809b46b9f13f2f3b0da66be581503243c08f7243b0c958902595060f9b1bdb0316e1d109a4aadf64a544df5c81d122a82999a8b0e05e3b701cac2b800d697f1eab39a0a40ad3cdac4fa7b40e9a37246e8c08b9dc36e30456f2b6b0d3fed3c34765056c21845a2b3637ef7cc9fdae7e26004001f319530f328f789a826a4a897d577718b09e440ac9713bb1fafb41a6aa62f5ad00b9eb86aa271bf78cabd7ec300e07bd2ec88faf76588584c45176d4a720e0a76c62b30251cd92cc715f48c9246ee77c17067584caaa133b74c70054c83425045750081cacd85c08c96ec86ebf7f2f9d1a19c734ef85a9c713978213d969d065a0059836611c8ba41fa7512bbb96adc064a08b47e9ba8049cbf32a92574a4b62f5deff01a9bb1d836d39360617b808d68b2d08dd89adff1d217d90a5ccdb3bc1b11aa07477213ac43
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
# Revision: 1.201
#

global_var session_id, enc_keys, seqn_w, seqn_r;
global_var local_channel, remote_channel;
global_var l_window_size, received_size;
global_var r_window_size, r_packet_size;
global_var dh_pub, dh_priv;
global_var _ssh_banner;
global_var _ssh_server_version;
global_var _ssh_supported_authentication;
global_var _ssh_cmd_error;
global_var _ssh_error;
global_var bugged_sshd, bugged_first, bugged_channels, bugged_rws, bugged_rps;
global_var initial_window_size, max_packet_size, window_base;
global_var _crypto_algo, _crypto_key_len, _crypto_block_size;
global_var _server_algo;
global_var server_host_key_blob;
global_var server_host_cert_blob;
global_var _ssh_protocol, _ssh_ltype;
global_var _ssh_socket;
global_var recv_buffer;
global_var KEY_LEN;
global_var _mac_algo, _mac_len;
global_var AOS_SSH, SONICWALL_SSH, ACOS_SSH;
global_var _ssh_current_port;
global_var _ssh_current_user;
global_var _exit_on_disconnect;

global_var g_ssh_timeout;

global_var _ssh_want_reply;

AOS_SSH = 0;
SU_NONE = 0;
SU_SU   = 1;
SU_SUDO = 2;
SU_SU_AND_SUDO = 3;
SU_DZDO = 4;
SU_PBRUN = 5;

include ("kerberos_func.inc");
include ("ssh1_func.inc");
include ("dump.inc");
include ("spad_log_func.inc");

######################################################################
# Message Numbers
#
# Note that these numbers are not unique, as several are context
# dependent. They are ordered first by category, then by number.
######################################################################

SSH_MSG_DISCONNECT = 1;
SSH_MSG_IGNORE = 2;
SSH_MSG_UNIMPLEMENTED = 3;
SSH_MSG_DEBUG = 4;

SSH_MSG_SERVICE_REQUEST = 5;
SSH_MSG_SERVICE_ACCEPT = 6;

SSH_MSG_KEXINIT = 20;
SSH_MSG_NEWKEYS = 21;

SSH_MSG_KEXDH_INIT = 30;
SSH_MSG_KEXDH_REPLY = 31;
SSH_MSG_KEXDH_GEX_INIT = 32;
SSH_MSG_KEXDH_GEX_REPLY = 33;
SSH_MSG_KEXDH_GEX_REQUEST = 34;

SSH_MSG_USERAUTH_REQUEST = 50;
SSH_MSG_USERAUTH_FAILURE = 51;
SSH_MSG_USERAUTH_SUCCESS = 52;
SSH_MSG_USERAUTH_BANNER = 53;

SSH_MSG_USERAUTH_GSSAPI_RESPONSE = 60;
SSH_MSG_USERAUTH_GSSAPI_TOKEN = 61;
SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE = 63;
SSH_MSG_USERAUTH_GSSAPI_ERROR = 64;
SSH_MSG_USERAUTH_GSSAPI_ERRTOK = 65;
SSH_MSG_USERAUTH_GSSAPI_MIC = 66;

SSH_MSG_USERAUTH_INFO_REQUEST = 60;
SSH_MSG_USERAUTH_INFO_RESPONSE = 61;

SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60;

SSH_MSG_USERAUTH_PK_OK = 60;

# RFC 4254, section 9.
SSH_MSG_GLOBAL_REQUEST  = 80;
SSH_MSG_REQUEST_SUCCESS = 81;
SSH_MSG_REQUEST_FAILURE = 82;

SSH2_MSG_CHANNEL_OPEN              = 90;
SSH2_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
SSH2_MSG_CHANNEL_OPEN_FAILURE      = 92;
SSH2_MSG_CHANNEL_WINDOW_ADJUST     = 93;
SSH2_MSG_CHANNEL_DATA              = 94;
SSH2_MSG_CHANNEL_EXTENDED_DATA     = 95;
SSH2_MSG_CHANNEL_EOF               = 96;
SSH2_MSG_CHANNEL_CLOSE             = 97;
SSH2_MSG_CHANNEL_REQUEST           = 98;
SSH2_MSG_CHANNEL_SUCCESS           = 99;
SSH2_MSG_CHANNEL_FAILURE           = 100;

# Reverse look up for MSG codes
global_var SSH_MSG_SYMBOLS_LOOKUP;
SSH_MSG_SYMBOLS_LOOKUP = make_array(
  1,  "SSH_MSG_DISCONNECT",
  2,  "SSH_MSG_IGNORE",
  3,  "SSH_MSG_UNIMPLEMENTED",
  4,  "SSH_MSG_DEBUG",
  5,  "SSH_MSG_SERVICE_REQUEST",
  6,  "SSH_MSG_SERVICE_ACCEPT",
  20, "SSH_MSG_KEXINIT",
  21, "SSH_MSG_NEWKEYS",
  30, "SSH_MSG_KEXDH_INIT",
  31, "SSH_MSG_KEXDH_REPLY",
  32, "SSH_MSG_KEXDH_GEX_INIT",
  33, "SSH_MSG_KEXDH_GEX_REPLY",
  34, "SSH_MSG_KEXDH_GEX_REQUEST",
  50, "SSH_MSG_USERAUTH_REQUEST",
  51, "SSH_MSG_USERAUTH_FAILURE",
  52, "SSH_MSG_USERAUTH_SUCCESS",
  53, "SSH_MSG_USERAUTH_BANNER",
  60, "SSH_MSG_USERAUTH_GSSAPI_RESPONSE",
  61, "SSH_MSG_USERAUTH_GSSAPI_TOKEN",
  63, "SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE",
  64, "SSH_MSG_USERAUTH_GSSAPI_ERROR",
  65, "SSH_MSG_USERAUTH_GSSAPI_ERRTOK",
  66, "SSH_MSG_USERAUTH_GSSAPI_MIC",
  60, "SSH_MSG_USERAUTH_INFO_REQUEST",
  61, "SSH_MSG_USERAUTH_INFO_RESPONSE",
  60, "SSH_MSG_USERAUTH_PASSWD_CHANGEREQ",
  60, "SSH_MSG_USERAUTH_PK_OK",
  80, "SSH_MSG_GLOBAL_REQUEST",
  81, "SSH_MSG_REQUEST_SUCCESS",
  82, "SSH_MSG_REQUEST_FAILURE",
  90, "SSH2_MSG_CHANNEL_OPEN",
  91, "SSH2_MSG_CHANNEL_OPEN_CONFIRMATION",
  92, "SSH2_MSG_CHANNEL_OPEN_FAILURE",
  93, "SSH2_MSG_CHANNEL_WINDOW_ADJUST",
  94, "SSH2_MSG_CHANNEL_DATA",
  95, "SSH2_MSG_CHANNEL_EXTENDED_DATA",
  96, "SSH2_MSG_CHANNEL_EOF",
  97, "SSH2_MSG_CHANNEL_CLOSE",
  98, "SSH2_MSG_CHANNEL_REQUEST",
  99, "SSH2_MSG_CHANNEL_SUCCESS",
  100,"SSH2_MSG_CHANNEL_FAILURE"
);

# Denotes that the next packet displayed should have
# the specified string scrubbed, FALSE means no
# packet info should be scrubbed
global_var SSH_PACKET_LOG_SCRUB_STRING;
SSH_PACKET_LOG_SCRUB_STRING = FALSE;

# Should packet logging occur?
global_var SSH_LOG_PACKETS;
SSH_LOG_PACKETS = FALSE;

##
# Logs a raw (unencrypted) packet to debugging logs if SSH_LOG_PACKETS is TRUE
# The log format imitates PuTTY's format
#
# @param data  packet data
# @param out   TRUE for outgoing packet FALSE for incoming packet
#
##
function ssh_log_rawpacket(data, out)
{
  if(!SSH_LOG_PACKETS) return;
  local_var line,dumped,msg,name;
  line   = "";
  dumped = "";
  if(!out) msg += 'Incoming raw data : \n';
  else     msg += 'Outgoing raw data : \n';
  if(data)
  {
    dumped = split(hexdump(ddata:data), sep:'\n');
    foreach line (dumped) msg += '\t'+line;
  }
  name = ((SCRIPT_NAME - ".nasl") - ".nbin") + "_ssh_pkt.log";
  spad_log(message:msg,name:name);
}

function ssh_log_command_and_response(command, response)
{
  if(!get_kb_item("global_settings/enable_plugin_debugging")) {
    return;
  }

  local_var resp;
  resp = response;
  if (!isnull(response)) {
    resp = chomp(substr(resp, 0, 30));
  }

  local_var err;
  err = _ssh_cmd_error;
  if (!isnull(_ssh_cmd_error)) {
    err = chomp(err);
  }

  local_var hostname = get_host_name();
  if(!hostname) hostname = get_host_ip();

  local_var message = '{' +
    '"plugin": ' + serialize(SCRIPT_NAME) + ', ' +
    '"command": ' + serialize(command) + ', ' +
    '"response": ' + serialize(resp) + ', ' +
    '"error": ' + serialize(err) + ', ' +
    '"hostname": ' + serialize(hostname) +
    '}';

  _add_ssh_cmd_log_entry(message:message);
  spad_log(message: message, name: 'ssh_commands.log');
}

global_var ssh_command_log_table_built = FALSE;

function _add_ssh_cmd_log_entry(message)
{
  if(!ssh_command_log_table_built)
  {
    query_scratchpad("CREATE TABLE IF NOT EXISTS ssh_cmd_log_json ( json_text text );");
    ssh_command_log_table_built = TRUE;
  }
  query_scratchpad("INSERT INTO ssh_cmd_log_json VALUES (?);", message);
}

##
# Logs an unencrypted packet to debugging logs if SSH_LOG_PACKETS is TRUE
# The log format imitates PuTTY's format
#
# - Normal packets will have their packet type trimmed 
#   before display
# - Kex packets will have their packet length, pad
#   length, kex type trimmed before display
# - Passwords will be sanitized scrub before packet
#   is displayed
#
# @param code  packet code (int/raw_int8)
# @param data  full unencrypted packet (raw data)
# @param out   TRUE for outgoing packet FALSE for incoming packet
#
##
function ssh_log_packet(code, data, out)
{
  if(!SSH_LOG_PACKETS) return;
  local_var line,dumped,symbol,prefix,redact,msg,name;

  if (typeof(code) == "int")
    code = raw_int8(i:code);
  code = ord(code);

  # Single byte message
  if(data && ord(data[0]) == code && strlen(data) == 1)
    data = FALSE;

  # Not kex
  if(data && ord(data[0]) == code)
    data = substr(data,1,strlen(data)-1);
  # Kex
  else if(data && strlen(data) > 5 && ord(data[5]) == code)
    data = substr(data,5,strlen(data)-1);

  #############################################
  # Scrub any string specified
  if(SSH_PACKET_LOG_SCRUB_STRING)
  {
    redact  = crap(data:"X", length:strlen(SSH_PACKET_LOG_SCRUB_STRING));
    data    = str_replace(string:data,find:SSH_PACKET_LOG_SCRUB_STRING,replace:redact);
  }
  #############################################

  line   = "";
  dumped = "";
  symbol = SSH_MSG_SYMBOLS_LOOKUP[code];
  prefix = "Incoming data ";

  if(out) prefix = "Outgoing data ";
  if(!symbol) symbol = "UNKNOWN";
  symbol += " ("+code+")";
  msg += prefix+symbol+'\n';

  if(data)
  {
    dumped = split(hexdump(ddata:data), sep:'\n');
    foreach line (dumped) msg += '\t'+line;
  }
  name = ((SCRIPT_NAME - ".nasl") - ".nbin") + "_ssh_pkt.log";
  spad_log(message:msg,name:name);
}

##
# Attempts SSHv2 authentication using the GSSAPI method.
#
# @param host Hostname for Kerberos.
# @param login Kerberos login.
# @param password Kerberos password.
# @param realm Kerberos realm
# @param user Username to attempt to log in with.
#
# @remark See RFC 4462 for details.
#
# @return True if successful, false otherwise.
##
function ssh_auth_gssapi(host, password, realm, user)
{
  local_var code, kerb_data, krb5, message, mic, oid, payload, res;
  local_var seq;

  # OID for Kerberos v5.
  krb5 = "1.2.840.113554.1.2.2";

  # Ask the server if it supports the specific authentication method
  # we're planning on attempting.
  payload =
    putstring(buffer:user) +
    putstring(buffer:"ssh-connection") +
    putstring(buffer:"gssapi-with-mic") +
    raw_int32(i:1) +
    putstring(buffer:der_encode_oid(oid:krb5));
  send_ssh_packet(code:SSH_MSG_USERAUTH_REQUEST, payload:payload);

  # Read the server's response.
  res = recv_ssh_packet();
  code = ord(res[0]);

  if (code != SSH_MSG_USERAUTH_GSSAPI_RESPONSE)
  {
    set_ssh_error(msg:"GSSAPI authentication failed : server does not support mechanism OID " + krb5 + " (ensure a valid username was provided).");
    return FALSE;
  }

  # Ensure the selected method matches the one we sent.
  oid = der_parse_oid(oid:getstring(buffer:res, pos:1));
  if (oid != krb5)
  {
    set_ssh_error(msg:"GSSAPI authentication failed : server selected mechanism OID " + oid + ".");
    return FALSE;
  }

  # Send first authentication request.
  seq = rand();
  kerb_data = kerberos_ssh(
    login    : user,
    password : password,
    realm    : realm,
    host     : host,
    seqnum   : seq
  );

  if (isnull(kerb_data))
  {
    set_ssh_error(msg:"GSSAPI authentication failed : could not get ticket from KDC (the SSH"+'\n'+
                      "credentials or Kerberos settings may be incorrect, or the Nessus"+'\n'+
                      "system's clock may be out of sync with the KDC's clock).");
    return FALSE;
  }

  SSH_PACKET_LOG_SCRUB_STRING = password;
  payload = putstring(buffer:kerb_data[1]);
  send_ssh_packet(code:SSH_MSG_USERAUTH_GSSAPI_TOKEN, payload:payload);
  SSH_PACKET_LOG_SCRUB_STRING = FALSE;

  # Read the server's response.
  res = recv_ssh_packet();
  code = ord(res[0]);

  if (code != SSH_MSG_USERAUTH_GSSAPI_TOKEN)
  {
    set_ssh_error(msg:"GSSAPI authentication failed : expected SSH_MSG_USERAUTH_GSSAPI_TOKEN"+'\n'+"but received code " + code + ".");
    return FALSE;
  }

  # Parse ticket from server's response.
  payload = check_gssapi_token(
    data      : getstring(buffer:res, pos:1),
    key       : kerb_data[0],
    realm     : realm,
    principal : user
  );
  if (isnull(payload))
  {
    set_ssh_error(msg:"GSSAPI authentication failed : checking GSSAPI token failed.");
    return FALSE;
  }

  # Send second authentication request.
  message =
    putstring(buffer:session_id) +
    raw_string(0x32) +
    putstring(buffer:user) +
    putstring(buffer:"ssh-connection") +
    putstring(buffer:"gssapi-with-mic");
  mic = gssapi_ssh_get_mic(data:message, key:kerb_data[0], seqnum:seq, enc_type:kerb_data[2]);
  payload = putstring(buffer:mic);
  send_ssh_packet(code:SSH_MSG_USERAUTH_GSSAPI_MIC, payload:payload);

  # Read the server's response.
  res = recv_ssh_packet();
  code = ord(res[0]);

  if (code != SSH_MSG_USERAUTH_SUCCESS)
  {
    set_ssh_error(msg:"GSSAPI authentication failed : credentials not accepted.");
    return FALSE;
  }

  return TRUE;
}

##
# Attempts SSHv2 authentication using the keyboard interactive method.
#
# @remark See RFC 4256 for details.
#
# @param password Password to attempt to log in with.
# @param user Username to attempt to log in with.
#
# @return True if successful, false otherwise.
##
function ssh_auth_keyboard(password, user)
{
  local_var code, crap, kb_ok, next, payload, prompt, prompts, res, inst;

  # Request keyboard-interactive authentication from the server.
  payload =
    putstring(buffer:user) +
    putstring(buffer:"ssh-connection") +
    putstring(buffer:"keyboard-interactive") +
    putstring(buffer:"en-US") +
    putstring(buffer:"");
  send_ssh_packet(code:SSH_MSG_USERAUTH_REQUEST, payload:payload);

  # Read the server's response.
  res = recv_ssh_packet();
  code = ord(res[0]);
  next = 1;

  # If we've already received a SUCCESS response and we have a blank
  # password, we're done
  if (code == SSH_MSG_USERAUTH_SUCCESS && !isnull(password) && strlen(password) == 0)
    return TRUE;

  if (code != SSH_MSG_USERAUTH_INFO_REQUEST)
  {
    set_ssh_error(msg:"Server did not reply with SSH_MSG_USERAUTH_INFO_REQUEST during"+'\n'+"keyboard-interactive exchange. It replied with : " + code + ".");
    return FALSE;
  }

  # Skip over name.
  crap = getstring(buffer:res, pos:next);
  next += 4 + strlen(crap);

  # Skip over instruction.
  inst = getstring(buffer:res, pos:next);
  next += 4 + strlen(inst);

  # Skip over language.
  crap = getstring(buffer:res, pos:next);
  next += 4 + strlen(crap);

  # Parse number of prompts.
  prompts = ntol(buffer:res, begin:next);
  next += 4;

  kb_ok = FALSE;
  if (prompts > 0)
  {
    prompt = getstring(buffer:res, pos:next);
    #
    # nb: Alcatel OS switches have a bug in their SSH server which make the prompt be a single space.
    if (
      buffer_contains_password_prompt(prompt, user) ||
      "'s password for keyboard-interactive method:" >< inst
    )
    {
      if  ( "'s password for keyboard-interactive method:" >< inst && prompt == " ") AOS_SSH = TRUE;
      kb_ok = TRUE;
    }
  }

  if (!kb_ok)
  {
    set_ssh_error(msg:"Remote server's keyboard-interactive method does not support password.");
    return FALSE;
  }

  # Send a single response, containing the password, to server.
  SSH_PACKET_LOG_SCRUB_STRING = password;
  payload = raw_int32(i:1) + putstring(buffer:password);
  send_ssh_packet(code:SSH_MSG_USERAUTH_INFO_RESPONSE, payload:payload);
  SSH_PACKET_LOG_SCRUB_STRING = FALSE;

  # Read response from server.
  res = recv_ssh_packet();
  code = ord(res[0]);

  # draft-ietf-secsh-auth-kbdinteract-06.txt
  #
  # Server should now send SSH_MSG_USERAUTH_INFO_REQUEST. REQUEST can
  # ask additional informations (like a new password). But if all is
  # correct num-prompts is set to 0 and client must reply with an
  # empty SSH_MSG_USERAUTH_INFO_RESPONSE. So we just send an empty
  # response and look if authentication works. If remote server asked
  # for additional information, authentication will just fail.
  if (code == SSH_MSG_USERAUTH_INFO_REQUEST)
  {
    if (
      "Changing password for " >< res ||                    # HPUX
      "Password change requested" >< res ||                 # SuSE 10
      "Password changing requested" >< res ||               # SuSE 9
      "Your password has expired" >< res ||                 # Solaris
      "New Password" >< res ||                              # FreeBSD
      "You are required to change your password" >< res     # Gentoo
    )
    {
      set_ssh_error(msg:"The password for the user '"+user+"' must be changed.");
      return FALSE;
    }

    # Send a blank response to the server.
    payload = raw_int32(i:0);
    send_ssh_packet(code:SSH_MSG_USERAUTH_INFO_RESPONSE, payload:payload);

    # Read response from server.
    res = recv_ssh_packet();
    code = ord(res[0]);
  }

  if (code != SSH_MSG_USERAUTH_SUCCESS)
  {
    set_ssh_error(msg:"Server did not reply with SSH_MSG_USERAUTH_SUCCESS during"+'\n'+"keyboard-interactive exchange. It replied with : " + code + ".");
    return FALSE;
  }

  return TRUE;
}

##
# Attempts SSHv2 authentication using the password method.
#
# @remark See RFC 4252 for details.
#
# @param password Password to attempt to log in with.
# @param user Username to attempt to log in with.
#
# @return True if successful, false otherwise.
##
function ssh_auth_password(password, user)
{
  local_var code, payload, res;

  # Request password authentication from the server.
  payload =
    putstring(buffer:user) +
    putstring(buffer:"ssh-connection") +
    putstring(buffer:"password") +
    raw_int8(i:0) +
    putstring(buffer:password);
  SSH_PACKET_LOG_SCRUB_STRING = password;
  send_ssh_packet(code:SSH_MSG_USERAUTH_REQUEST, payload:payload);
  SSH_PACKET_LOG_SCRUB_STRING = FALSE;

  # Read the server's response.
  res = recv_ssh_packet();
  code = ord(res[0]);

  if (code == SSH_MSG_USERAUTH_PASSWD_CHANGEREQ)
  {
    set_ssh_error(msg:"The password for the user '"+user+"' must be changed.");
    return FALSE;
  }

  if (code != SSH_MSG_USERAUTH_SUCCESS)
  {
    set_ssh_error(msg:"Password authentication failed.");
    return FALSE;
  }

  return TRUE;
}

function ssh_putenv(key, value)
{
 local_var payload;

 payload = raw_int32(i:remote_channel) + putstring(buffer:"env") + raw_int8(i:0) + putstring(buffer:key) + putstring(buffer:value);
 # SSH_MSG_CHANNEL_REQUEST == 98
 send_ssh_packet(payload:payload, code:raw_int8(i:98));
}

##
# Attempts SSHv2 authentication when the 'none' authentication request succeeds
# but the service prompts for a username / password (eg, Cisco Wireless LAN
# Controllers).
#
# @param user Username to attempt to log in with.
# @param password Password to attempt to log in with.
#
# @remark opens an SSH channel and leaves it open when the function exits.
#
# @return True if successful, false otherwise.
##
function ssh_auth_none(user, password, term)
{
  local_var auth_success, cmd_prompt, iter, last5, line, payload, spass, tempbuf, val;

  if (isnull(term)) term = "vt100";

  if (ssh_open_channel() != 0)
  {
    _ssh_cmd_error = "Nessus failed to open a new SSH channel. " + get_ssh_error();
    return FALSE;
  }

  payload = raw_int32(i:remote_channel) + putstring(buffer:"pty-req") + raw_int8(i:0) +
            putstring(buffer:term) + raw_int32(i:80) + raw_int32(i:24) + raw_int32(i:640) + raw_int32(i:480) +
            putstring(buffer:
                             raw_int8(i:53) + raw_int32(i:0) +
                 raw_int8(i:72) + raw_int32(i:0) +
                 raw_int8(i:0));

  # SSH_MSG_CHANNEL_REQUEST == 98
  send_ssh_packet(payload:payload, code:raw_int8(i:98));

  payload = raw_int32(i:remote_channel) + putstring(buffer:"shell") + raw_int8(i:0) ;

  # SSH_MSG_CHANNEL_REQUEST == 98
  send_ssh_packet(payload:payload, code:raw_int8(i:98));

  payload = recv_ssh_packet();

  while((ord(payload[0]) == SSH2_MSG_CHANNEL_WINDOW_ADJUST) || (ord(payload[0]) == SSH2_MSG_CHANNEL_EXTENDED_DATA) || (ord(payload[0])  == SSH2_MSG_CHANNEL_REQUEST))
  {
    if (ord(payload[0]) == SSH2_MSG_CHANNEL_WINDOW_ADJUST)
    {
      payload = ntol(buffer:payload, begin:5);
      r_window_size += payload;
    }
    else if (ord(payload[0]) == SSH2_MSG_CHANNEL_EXTENDED_DATA)
    {
      payload = getstring(buffer:payload, pos:9);
      _ssh_cmd_error += payload;
      val = update_window_size(size:strlen(payload));
      if (val != 0) break;
    }
    payload = recv_ssh_packet();
  }

  auth_success = FALSE;
  iter = 0;
  spass = 0;
  while ((ord(payload[0]) != SSH2_MSG_CHANNEL_CLOSE) && (ord(payload[0]) != 0))
  {
    iter++;

    if (ord(payload[0]) == SSH2_MSG_CHANNEL_REQUEST)
    {
      if (iter > 5) return 0;

      payload = getstring(buffer:payload, pos:5);

      if ("exit-status" >!< payload && "eow@openssh.com" >!< payload && "keepalive@openssh.com" >!< payload)
        break;

      payload = recv_ssh_packet();
    }
    else if (ord(payload[0]) == SSH_MSG_DISCONNECT)
    {
      _ssh_cmd_error = strcat(
        _ssh_cmd_error,
        'The host responded with the following error message : \'', getstring(buffer:payload, pos:5), '\'.'
      );
      ssh_close_channel(end:0);
      return NULL;
    }
    else if ((ord(payload[0]) == SSH2_MSG_CHANNEL_WINDOW_ADJUST))
    {
      payload = ntol(buffer:payload, begin:5);
      r_window_size += payload;
    } 
    else if ((ord(payload[0]) == SSH2_MSG_CHANNEL_DATA) || (ord(payload[0]) == SSH2_MSG_CHANNEL_EXTENDED_DATA))
    {
      tempbuf = getstring(buffer:payload, pos:5);
      val = update_window_size(size:strlen(tempbuf));
      if (val != 0)
      {
        break;
      }

      if (strlen(tempbuf) > 5) last5 = substr(tempbuf, strlen(tempbuf) - 6, strlen(tempbuf) - 1);
      else last5 = tempbuf;

      if (spass == 0)
      {
        if ("SonicWALL, Inc." >< tempbuf)
        {
          SONICWALL_SSH = TRUE;
          if ('\nPassword:' >< tempbuf)
          {
            payload = raw_int32(i:remote_channel) + putstring(buffer:password+'\n');
            send_ssh_packet(payload:payload, code:raw_int8(i:94));
            spass = 2;
          }
        }


        if ('\nUser:' >< tempbuf)
        {
          payload = raw_int32(i:remote_channel) + putstring(buffer:user+'\n');
          send_ssh_packet(payload:payload, code:raw_int8(i:94));
          spass = 1;
        }
        else if ("$" >< last5 || "#" >< last5 || ">" >< last5 || "%" >< last5) break;
      }
      else if (spass == 1)
      {
        if ('\nPassword:' >< tempbuf)
        {
          payload = raw_int32(i:remote_channel) + putstring(buffer:password+'\n');
          send_ssh_packet(payload:payload, code:raw_int8(i:94));
          spass = 2;
        }
        else if ("$" >< last5 || "#" >< last5 || ">" >< last5 || "%" >< last5) break;
      }
      else if (spass < 5)
      {
        if ('must be changed' >< tempbuf && SONICWALL_SSH)
        {
          set_ssh_error(msg:"The password for the user '"+user+"' must be changed.");
          return FALSE;
        }

        if ("$" >< last5 || "#" >< last5 || ">" >< last5 || "%" >< last5)
        {
          auth_success = TRUE;

          foreach line (split(tempbuf))
          {
            # empty
          }
          cmd_prompt = line;
          replace_kb_item(name:"/tmp/ssh_cmd/cmd_prompt", value:cmd_prompt);
          break;
        }
        else if ('\nUser:' >< tempbuf) break;
        else spass++;
      }
      else break;

      payload = recv_ssh_packet();
    }
  }

  return auth_success;
}

##
# Test a SSHv2 server for public key acceptance for a user.
#
# @param pub Public key or certificate.
# @param user Username to attempt to log in with.
#
# @return True if the key is accepted, false otherwise.
##
function ssh_login_public_key_only(pub, login)
{
  local_var buf, prot, ret, client_ver, server_version;

  init();

  client_ver = kb_ssh_client_ver();

  _ssh_current_user = login;

  # Exchange protocol version identification strings with the server.
  server_version = ssh_exchange_identification();
  if (!server_version)
  {
    set_ssh_error(msg: "Nessus did not receive server's version.");
    return FALSE;
  }

  _ssh_server_version = server_version;

  # only ssh v2 is supported
  if (_ssh_protocol != 2)
  {
    set_ssh_error(msg: "Nessus only supports SSH v2 for public key only authentication.");
    return FALSE;
  }

  # key exchange
  ret = ssh_kex2(server_version:server_version, nofingerprint:FALSE);
  if (ret != 0)
  {
    set_ssh_error(msg: "SSH key exchange failed.");
    return FALSE;
  }

  # Check if user authentication is supported.
  if (!ssh_req_svc("ssh-userauth"))
  {
    set_ssh_error(msg: "SSH user authentication is not supported.");
    return FALSE;
  }

  return ssh_userauth2_public_key_only(pub:pub, user:login);
}

##
# Tries to perform user auth with just a public key.
#
# @param pub Public key or certificate.
# @param user Username to attempt to log in with.
#
# @return True if the key is accepted, false otherwise.
##
function ssh_userauth2_public_key_only(pub, user)
{
  local_var code, key, payload, res;

  # Check that the required arguments are provided.
  if (!pub || !user)
  {
    set_ssh_error(msg: "User or public key is invalid.");
    return FALSE;
  }

  # Parse public key.
  key = ssh_parse_public_key_only(pub:pub);
  if (isnull(key))
  {
    set_ssh_error(msg:"Cannot parse public key.");
    return FALSE;
  }

  # Create key-agnostic portion of message.
  payload =
    putstring(buffer:user) +
    putstring(buffer:"ssh-connection") +
    putstring(buffer:"publickey") +
    raw_int8(i:0) +
    putstring(buffer:key["type"]) +
    putstring(buffer:key["pub"]);

  # Send message to server.
  SSH_PACKET_LOG_SCRUB_STRING = key["pub"];
  send_ssh_packet(code:SSH_MSG_USERAUTH_REQUEST, payload:payload);
  SSH_PACKET_LOG_SCRUB_STRING = FALSE;

  # Read the server's response.
  res = recv_ssh_packet();
  code = ord(res[0]);

  # Check if the public key is accepted.
  if (code == SSH_MSG_USERAUTH_PK_OK)
     return TRUE;

  set_ssh_error(msg: "Server did not reply with SSH_MSG_USERAUTH_PK_OK.");
  return FALSE;
}

##
# Parse public key only.
#
# @remark See RFC 4462 for details.
#
# @param pub Public key or certificate.
#
# @return Array of key information.
##
function ssh_parse_public_key_only(pub)
{
  local_var blob, errmsg, key, line, lines, next, nonce;

  if ("---" >< pub)
  {
    # Parse key formatted in the SSH Public Key File Format.
    blob = "";
    lines = split(pub, sep:'\n', keep:FALSE);

    foreach line (lines)
    {
      # Skip lines that aren't part of the key itself.
      if ("---" >< line || ":" >< line)
        continue;

      # Remove DOS-style line ending remnants.
      if ('\r' >< line)
        line -= '\r';

      blob += line;
    }
  }
  else
  {
    # Parse key formatted in the OpenSSH public key file format.
    blob = ereg_replace(
      pattern : "[^ ]* ([^ ]*)( .*)?$",
      string  : chomp(pub),
      replace : "\1"
    );
  }

  # Convert to binary form.
  if (strlen(blob)) blob = base64decode(str:blob);
  if (strlen(blob) == 0)
  {
    errmsg = "Nessus failed to parse the public key.";
    set_ssh_error(msg:errmsg);
    if (defined_func("report_error"))
      report_error(title:"SSH Public-Key Authentication Failure", message:errmsg, severity:1);
    return NULL;
  }

  # Initialize key structure.
  key = make_array("pub", blob);

  # Parse type of key.
  key["type"] = getstring(buffer:blob, pos:0);
  next = 4 + strlen(key["type"]);

  # if this is a certificate, skip over the nonce field if necessary.
  # in v00 the nonce is several fields after the relevant RSA and DSA data, but
  # in v01 the nonce is right after the key type
  # for info on the formats, see the different revisions of http://www.openssh.com/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys
  # this is a quick solution (done in lieu of actually parsing the certificate) but it works
  if (_is_valid_openssh_cert_type(key["type"]) && key["type"] !~ '-cert-v00@openssh.com$')
  {
    nonce = getstring(buffer:blob, pos:next);
    next += 4 + strlen(nonce);
  }

  if ("ssh-rsa" >< key["type"])
  {
    # Store the signature algorithm.
    key["alg"] = "ssh-rsa";

    # Parse exponent from RSA key.
    key["e"] = getstring(buffer:blob, pos:next);
    next += 4 + strlen(key["e"]);

    # Parse modulus from RSA key.
    key["n"] = getstring(buffer:blob, pos:next);
  }
  else if ("ssh-dss" >< key["type"])
  {
    # Store the signature algorithm.
    key["alg"] = "ssh-dss";

    # Parse 'p' parameter from DSA key.
    key["p"] = getstring (buffer:blob, pos:next);
    next += 4 + strlen(key["p"]);

    # Parse 'q' parameter from DSA key.
    key["q"] = getstring (buffer:blob, pos:next);
    next += 4 + strlen(key["q"]);

    # Parse 'g' parameter from DSA key.
    key["g"] = getstring (buffer:blob, pos:next);
    next += 4 + strlen(key["g"]);

    # Parse 'y' parameter from DSA key.
    key["y"] = getstring(buffer:blob, pos:next);
  }
  else
  {
    # If we extract the type and that's printable...
    if (key["type"] && key["type"] =~ "^[A-Za-z0-9-]+$")
    {
      errmsg = "The SSH public key used for the scan is an unsupported type (" + key["type"] + ").";
      set_ssh_error(msg:errmsg);
      if (defined_func("report_error"))
        report_error(title:"SSH Public-Key Authentication Failure", message:errmsg, severity:1);
    }
    else
    {
      # nb: key["type"] for RSA1 keys generated by OpenSSH will not exist;
      #     don't call it invalid.
      errmsg = "The SSH public key used for the scan is unsupported or invalid.";
      set_ssh_error(msg:errmsg);
      if (defined_func("report_error"))
        report_error(title:"SSH Public-Key Authentication Failure", message:errmsg, severity:1);
    }
    return NULL;
  }

  return key;
}

##
# Attempts SSHv2 authentication using a publickey method.
#
# @remark See RFC 4252 for details.
#
# @param passphrase Passphrase to decrypt private key.
# @param priv Private key, possibly encrypted.
# @param pub Public key or certificate.
# @param user Username to attempt to log in with.
#
# @return True if successful, false otherwise.
##
function ssh_auth_publickey(passphrase, priv, pub, user)
{
  local_var code, hash, key, payload, res, signature;

  # Check that the required arguments are provided.
  # A public key is only required on scanners prior to Nessus 6.
  if (!priv || (!pub && (!defined_func("nasl_level") || nasl_level() < 6000)) || !user)
    return FALSE;

  # Parse public and private keys.
  key = ssh_parse_keys(pub:pub, priv:priv, passphrase:passphrase);
  if (isnull(key))
    return FALSE;

  # Create key-agnostic portion of message.
  payload =
    putstring(buffer:user) +
    putstring(buffer:"ssh-connection") +
    putstring(buffer:"publickey") +
    raw_int8(i:1) +
    putstring(buffer:key["type"]) +
    putstring(buffer:key["pub"]);

  # Hash the message.
  hash = SHA1(
    putstring(buffer:session_id) +
    raw_int8(i:SSH_MSG_USERAUTH_REQUEST) +
    payload
  );

  if ("ssh-rsa" >< key["type"])
  {
    # Sign the message.
    signature = rsa_sign(
      e    : key["e"],
      n    : key["n"],
      d    : key["priv"],
      data : hash
    );
  }
  else if ("ssh-dss" >< key["type"])
  {
    # Sign the message.
    signature = dsa_do_sign(
      p    : key["p"],
      q    : key["q"],
      g    : key["g"],
      pub  : key["y"],
      priv : key["priv"],
      data : hash
    );
  }

  if (!signature)
  {
    set_ssh_error(msg:"Error during client's signature computing.");
    return FALSE;
  }

  # Format signature for inclusion in payload.
  signature = putstring(buffer:key["alg"]) + putstring(buffer:signature);

  # Add signature to payload, and send signed message to server.
  payload += putstring(buffer:signature);
  SSH_PACKET_LOG_SCRUB_STRING = key["pub"];
  send_ssh_packet(code:SSH_MSG_USERAUTH_REQUEST, payload:payload);
  SSH_PACKET_LOG_SCRUB_STRING = FALSE;

  # Read the server's response.
  res = recv_ssh_packet();
  code = ord(res[0]);

  # workaround for customers using Dell Defender PAM modules with 2FA
  # partial authentication with public key.  Assumes the 2FA (which is keyboard-interactive)
  # is disabled for given user, so no password is required.
  if(code == SSH_MSG_USERAUTH_FAILURE && getstring(buffer:res, pos:1) == 'keyboard-interactive')
  {
    ssh_auth_keyboard(password:'', user:user);
    payload = raw_int32(i:0);
    send_ssh_packet(code:SSH_MSG_USERAUTH_INFO_RESPONSE, payload:payload);

    res = recv_ssh_packet();
    code = ord(res[0]);
  }

  # Check if we've successfully authenticated.
  if (code == SSH_MSG_USERAUTH_SUCCESS || code == SSH_MSG_USERAUTH_PK_OK)
     return TRUE;

  return FALSE;
}

##
# Parse private key and either public key or certificate.
#
# @remark See RFC 4462 for details.
#
# @param passphrase Passphrase to decrypt private key.
# @param priv Private key, possibly encrypted.
# @param pub Public key or certificate.
#
# @return Array of key information.
##
function ssh_parse_keys(passphrase, priv, pub)
{
  local_var rsa_key, dsa_key, key, errmsg, tla_type;

  if (isnull(pub) && defined_func('nasl_level') && nasl_level() >= 6000)
  {
    key = make_array();
    rsa_key = pem_to_rsa2(priv:priv, passphrase:passphrase);

    if (!isnull(rsa_key))
    {
      key["e"] = rsa_key["e"];
      key["n"] = rsa_key["n"];
      key["priv"] = rsa_key["d"];
      key["type"] = "ssh-rsa";
      key["alg"] = "ssh-rsa";
      key["pub"] = encode_ssh2_rsa_public_key(e:rsa_key["e"], n:rsa_key["n"]);
    }
    else
    {
      dsa_key = pem_to_dsa2(priv:priv, passphrase:passphrase);

      if (!isnull(dsa_key))
      {
        key["p"] = dsa_key["p"];
        key["q"] = dsa_key["q"];
        key["g"] = dsa_key["g"];
        key["y"] = dsa_key["pub_key"];
        key["priv"] = dsa_key["priv_key"];
        key["type"] = "ssh-dss";
        key["alg"] = "ssh-dss";
        key["pub"] = encode_ssh2_dsa_public_key(p:dsa_key["p"], q:dsa_key["q"], g:dsa_key["g"], y:dsa_key["pub_key"]);
      }
    }
  }
  else
  {
  key = ssh_parse_public_key_only(pub:pub);
  if(isnull(key))
    return NULL;

  # Parse the private key
  if ("ssh-rsa" >< key["type"])
  {
    key["priv"] = pem_to_rsa(priv:priv, passphrase:passphrase);
    tla_type = "RSA";
  }
  else if ("ssh-dss" >< key["type"])
  {
    key["priv"] = pem_to_dsa(priv:priv, passphrase:passphrase);
    tla_type = "DSA";
  }
  }

  if (!key["priv"])
  {
    if (isnull(tla_type))
      errmsg = "Nessus failed to load the SSH private key. Is the associated passphrase correct?";
    else
      errmsg = "Nessus failed to load the SSH private key (" + tla_type + "). Is the associated passphrase correct?";
    set_ssh_error(msg:errmsg);
    if (defined_func("report_error"))
      report_error(title:"SSH Public-Key Authentication Failure", message:errmsg, severity:1);
    return NULL;
  }

  return key;
}

# ssh_hex2raw() copied from misc_func.inc as we don't want to taint ssh_func.inc with
# a third-party include
function ssh_hex2raw(s)
{
 local_var i, j, ret, l;

 s = chomp(s);  # remove trailing blanks, CR, LF...
 l = strlen(s);
 if (l % 2) display("ssh_hex2raw: odd string: ", s, "\n");
 for(i=0;i<l;i+=2)
 {
  if(ord(s[i]) >= ord("0") && ord(s[i]) <= ord("9"))
        j = int(s[i]);
  else
        j = int((ord(s[i]) - ord("a")) + 10);

  j *= 16;
  if(ord(s[i+1]) >= ord("0") && ord(s[i+1]) <= ord("9"))
        j += int(s[i+1]);
  else
        j += int((ord(s[i+1]) - ord("a")) + 10);
  ret += raw_string(j);
 }
 return ret;
}

function kb_ssh_login()
{
 return string(get_kb_item("Secret/SSH/login"));
}

function kb_ssh_password()
{
 return string(get_kb_item("Secret/SSH/password"));
}

function kb_ssh_privatekey()
{
 local_var priv;

 priv = string(get_kb_item("Secret/SSH/privatekey"));
 if (isnull(priv)) return NULL;

 return ssh_hex2raw(s:priv);
}

function kb_ssh_publickey()
{
 return string(get_kb_item("Secret/SSH/publickey"));
}

function kb_ssh_passphrase()
{
 return string(get_kb_item("Secret/SSH/passphrase"));
}

function kb_ssh_certificate()
{
 return get_kb_item("Secret/SSH/certificate");
}

##
# Loads Kerberos settings for the ith (zero-based) additional SSH account.
#
# For Nessus >= 6, this returns the Kerberos settings associated with ith set of SSH creds,
# For Nessus < 6, this returns global Kerberos settings that apply to all Windows and SSH creds
#
# @return the kerberos realm, or
#         NULL if no kerberos data was loaded
##
function kb_load_alt_kerberos_data()
{
  if (get_kb_item("Kerberos/global"))
    return kb_ssh_realm();

  local_var i, host, port, realm, use_tcp;
  i = _FCT_ANON_ARGS[0];
  if (i !~ "^\d+$") return NULL;

  host = get_kb_item(strcat("Kerberos/SSH/", i, "/kdc_hostname"));
  port = get_kb_item(strcat("Kerberos/SSH/", i, "/kdc_port"));
  realm = get_kb_item(strcat("Kerberos/SSH/", i, "/realm"));
  use_tcp = get_kb_item(strcat("Kerberos/SSH/", i, "/kdc_use_tcp"));

  if (host && port && realm)
  {
    replace_kb_item(name:"Kerberos/SSH/realm", value:realm);
    # used by open_sock_ex() (nessus >= 6)
    replace_kb_item(name:"Secret/SSH/kdc_hostname", value:host);
    replace_kb_item(name:"Secret/SSH/kdc_port", value:int(port));
    # used by open_sock_kdc() (nessus < 6)
    replace_kb_item(name:"Secret/kdc_hostname", value:host);
    replace_kb_item(name:"Secret/kdc_port", value:int(port));
    if (use_tcp)
    {
      replace_kb_item(name:"Kerberos/SSH/kdc_use_tcp", value:TRUE); # open_sock_ex()
      replace_kb_item(name:"Secret/kdc_use_tcp", value:TRUE); # open_sock_kdc()
    }

    return realm;
  }

  return NULL;
}

function kb_ssh_realm()
{
 return string(get_kb_item("Kerberos/SSH/realm"));
}

function kb_ssh_host()
{
 return get_host_name();
}

function kb_ssh_transport()
{
 local_var r;
 local_var port, pref;

 pref = get_kb_item("Secret/SSH/PreferredPort");
 r = get_kb_list("Services/ssh");
 if ( ! isnull(r) )
 {
  r = make_list(r);
  # Try to use the PreferredPort (if specified)
  if ( pref > 0 ) foreach port ( r )  { if ( port == pref ) return port; }
  # Try to use port 22
  foreach port ( r )  { if ( port == 22 ) return port; }

  # Otherwise, use the first port available
  port = r[0];
  if (port) return port;
 }

 if ( pref && get_port_state(pref) ) return pref;
 return 22; # Default
}

function kb_ssh_client_ver()
{
 local_var ver;
 ver = get_kb_item("SSH/clientver");

 if (isnull(ver)) ver = "OpenSSH_5.0";

 return ver;
}

##
# Returns the private key of the alternate SSH account.
#
# This will not return the private key of the 0th SSH account, that is
# handled by ssh_settings.nasl.
#
# @anonparam i index of the alternate SSH account
#
# @return private key of the ith SSH account if one has been provided, or
#         NULL otherwise
##
function kb_ssh_alt_privatekey()
{
 local_var i, priv;
 i = _FCT_ANON_ARGS[0];

 priv = string(get_kb_item(strcat("Secret/SSH/", i, "/privatekey")));
 if (isnull(priv)) return NULL;

 return ssh_hex2raw(s:priv);
}

##
# Loads escalation data tied to any of the 5+ alternate SSH accounts
#
# ssh_cmd() looks for the same KB values to perform privilege escalation.
# by default, the privilege escalation data for the main SSH account is used.
# this function allows using privilege escalation data for the alternate accounts,
# which involves copying data into those expected KB values.
#
# This will not load escalation data for the 0th SSH account in the policy, which
# is loaded by ssh_settings.nasl.
#
# @anonparam i index of alternate SSH account to load data for
##
function kb_load_alt_escalation_data()
{
  local_var i, root, sudo, sudo_method, su_login, sudo_password, enable_password, sudo_path;
  i = _FCT_ANON_ARGS[0];
  if (i !~ "^\d+$") return;

  sudo = get_kb_item(strcat("Secret/SSH/", i, "/sudo"));
  if (!isnull(sudo))
    replace_kb_item(name:"Secret/SSH/sudo", value:sudo);

  sudo_method = get_kb_item(strcat("Secret/SSH/", i, "/sudo_method"));
  if (!isnull(sudo_method))
    replace_kb_item(name:"Secret/SSH/sudo_method", value:sudo_method);

  root = get_kb_item(strcat("Secret/SSH/", i, "/root"));
  if (!isnull(root))
    replace_kb_item(name:"Secret/SSH/root", value:root);

  su_login = get_kb_item(strcat("Secret/SSH/", i, "/su-login"));
  if (!isnull(su_login))
    replace_kb_item(name:"Secret/SSH/su-login", value:su_login);

  sudo_password = get_kb_item(strcat("Secret/SSH/", i, "/sudo-password"));
  if (!isnull(sudo_password))
    replace_kb_item(name:"Secret/SSH/sudo-password", value:sudo_password);

  enable_password = get_kb_item(strcat("Secret/SSH/", i, "/enable-password"));
  if (!isnull(enable_password))
    replace_kb_item(name:"Secret/SSH/enable-password", value:enable_password);

  sudo_path = get_kb_item(strcat("Secret/SSH/", i, "/sudo_path"));
  if (!isnull(sudo_path))
    replace_kb_item(name:"Secret/SSH/sudo_path", value:sudo_path);
}

function kb_rm_ssh_data()
{
  rm_kb_item(name:'Secret/SSH/sudo_method');
  rm_kb_item(name:'Secret/SSH/sudo');
  rm_kb_item(name:'Secret/SSH/sudo_path');
  rm_kb_item(name:'Secret/SSH/root');
  rm_kb_item(name:'Secret/SSH/sudo-password');
  rm_kb_item(name:'Secret/SSH/enable-password');
  rm_kb_item(name:'Secret/SSH/su-login');

  # 5.x stores KDC data in Secret/kdc_* and it applies equally to all creds, so it should never be deleted from the KB.
  # 6.x stores KDC data in Secret/SSH/kdc* and it only applies to one set of creds, so it needs to be deleted if auth fails
  if (get_kb_item('Secret/SSH/kdc_hostname'))
  {
    rm_kb_item(name:'Secret/SSH/kdc_hostname');
    rm_kb_item(name:'Secret/SSH/kdc_port');
    rm_kb_item(name:'Kerberos/SSH/kdc_use_tcp');
    rm_kb_item(name:'Kerberos/SSH/realm');
  }
}

##
# Checks whether it appears that the given data is a valid OpenSSH certificate.
# ECDSA and ED25519 are recognized as valid even though it is currently not supported by this library.
#
# @anonparam cert certificate to validate (this function expects data from an OpenSSH certificate file)
# @return TRUE if "cert" appears to be a valid OpenSSH certificate,
#         FALSE otherwise
##
function is_valid_openssh_certificate()
{
  local_var cert, valid_cert, fields, key_type;
  cert = _FCT_ANON_ARGS[0];

  fields = split(cert, sep:' ', keep:FALSE);
  key_type = fields[0];

  return _is_valid_openssh_cert_type(key_type);
}

##
# Determines if the given key type is supported by Nessus for OpenSSH certificates
#
# @anonparam cert to check
# @return TRUE if "cert" uses an OpenSSH certificate key type supported by Nessus,
#         FALSE otherwise
##
function is_supported_openssh_cert_key_type()
{
  local_var cert, fields, key_type;
  cert = _FCT_ANON_ARGS[0];
  fields = split(cert, sep:' ', keep:FALSE);
  key_type = fields[0];

  return 
    key_type == 'ssh-rsa-cert-v00@openssh.com' ||
    key_type == 'ssh-dss-cert-v00@openssh.com' ||
    key_type == 'ssh-rsa-cert-v01@openssh.com' ||
    key_type == 'ssh-dss-cert-v01@openssh.com';
}

##
# Determines if the given key type is a valid OpenSSH certificate type
#
# @remark for valid key types, see http://www.openssh.com/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys
# @anonparam key_type key type to check
# @return TRUE if "key_type" is a valid OpenSSH certificate type,
#         FALSE otherwise
##
function _is_valid_openssh_cert_type()
{
  local_var key_type;
  key_type = _FCT_ANON_ARGS[0];

  # v00 was replaced with v01 in OpenSSH 5.6. v00 will be deprecated, but it is possible some clients/servers are still using it
  return
    key_type == 'ssh-rsa-cert-v00@openssh.com' ||
    key_type == 'ssh-dss-cert-v00@openssh.com' ||
    key_type == 'ssh-rsa-cert-v01@openssh.com' ||
    key_type == 'ssh-dss-cert-v01@openssh.com' ||
    key_type == 'ecdsa-sha2-nistp256-cert-v01@openssh.com' ||
    key_type == 'ecdsa-sha2-nistp384-cert-v01@openssh.com' ||
    key_type == 'ecdsa-sha2-nistp521-cert-v01@openssh.com' ||
    key_type == 'ssh-ed25519-cert-v01@openssh.com';
}

#-----------------------------------------------------------------#
# Set SSH debugging error msg                                     #
#-----------------------------------------------------------------#
function set_ssh_error(msg)
{
 _ssh_error = msg;
}

#-----------------------------------------------------------------#
# Get SSH debugging error msg                                     #
#-----------------------------------------------------------------#
function get_ssh_error()
{
 return _ssh_error;
}

##
# Sets flag used for validating responses.
#
# @param [_FCT_ANON_ARGS[0]:boolean] TRUE if responses should be validated, FALSE otherwise
##
function set_ssh_want_reply()
{
  _ssh_want_reply = (_FCT_ANON_ARGS[0] != FALSE);
}

#-----------------------------------------------------------------#
# Get SSH server's version                                        #
#-----------------------------------------------------------------#
function get_ssh_supported_authentication()
{
 return _ssh_supported_authentication;
}

#-----------------------------------------------------------------#
# Get SSH server's version                                        #
#-----------------------------------------------------------------#
function get_ssh_server_version()
{
 return _ssh_server_version;
}

##
# Sets read timeout when reading SSH banner.
#
# @param [_FCT_ANON_ARGS[0]:int] timeout in seconds
#
# @return [int]
##
function set_ssh_read_timeout()
{
  local_var to;
  local_var old;

  to = _FCT_ANON_ARGS[0];
  old = g_ssh_timeout;
  if (isnull(to) || to <= 0)
  {
    g_ssh_timeout = NULL;
  }
  else
  {
    g_ssh_timeout = to;
  }
  return old;
}

##
# Gets read timeout when reading SSH banner.
#
# @return [string] timeout in seconds
##
function get_ssh_read_timeout()
{
  local_var timeout;

  if (isnull(g_ssh_timeout))
  {
    timeout = int(get_preference("checks_read_timeout"));
    if (timeout <= 0) timeout = 5;
    return timeout;
  }
  else
    return g_ssh_timeout;
}

#-----------------------------------------------------------------#
# Get SSH banner                                                  #
#-----------------------------------------------------------------#
function get_ssh_banner()
{
 return _ssh_banner;
}

#-----------------------------------------------------------------#
# Get SSH public key                                              #
#-----------------------------------------------------------------#
function get_server_public_key()
{
 return server_host_key_blob;
}

#-----------------------------------------------------------------#
# Convert network long (buffer) to long                           #
#-----------------------------------------------------------------#
function ntol(buffer,begin)
{
 local_var len;

 len = 16777216*ord(buffer[begin]) +
       ord(buffer[begin+1])*65536 +
       ord(buffer[begin+2])*256 +
       ord(buffer[begin+3]);

 return len;
}

##
# Convert integer to 32-bit network representation.
#
# @param i Integer to convert.
#
# @remark The i parameter may also be given anonymously.
#
# @return String representing 32-bit integer.
##
function raw_int32(i)
{
  if (isnull(i))
    i = _FCT_ANON_ARGS[0];

  return raw_string(
    (i >> 24) & 255,
    (i >> 16) & 255,
    (i >>  8) & 255,
    (i      ) & 255
  );
}

##
# Convert integer to 8-bit network representation.
#
# @param i Integer to convert.
#
# @remark The i parameter may also be given anonymously.
#
# @return String representing 8-bit integer.
##
function raw_int8(i)
{
  if (isnull(i))
    i = _FCT_ANON_ARGS[0];

  return raw_string(i & 255);
}

#-----------------------------------------------------------------#
# Init packet sequence number and channel number                  #
#-----------------------------------------------------------------#
function init()
{
 # sequence packet = 0
 seqn_w = seqn_r = 0;
 local_channel = 0;
 _ssh_ltype = 0;
 _ssh_banner = "";
 _ssh_server_version = "";
 _ssh_supported_authentication = "";
 _ssh_cmd_error = "";
 _ssh_error = "";
 _ssh_want_reply = 0;
 max_packet_size = 32*1024;
 initial_window_size = max_packet_size * 2;
 window_base = initial_window_size * 2;
 bugged_sshd = 0;
 bugged_first = 1;
}

#-----------------------------------------------------------------#
# Init crypto data (key length, block size, ...)                  #
#-----------------------------------------------------------------#
function init_crypto_data()
{
 if (_crypto_algo == "blowfish-cbc")
 {
  _crypto_block_size = 8;
  _crypto_key_len = 16;
 }
 else if (_crypto_algo == "aes128-cbc" || _crypto_algo == "aes128-ctr")
 {
  _crypto_block_size = 16;
  _crypto_key_len = 16;
 }
 else if (_crypto_algo == "aes192-cbc" || _crypto_algo == "aes192-ctr")
 {
  _crypto_block_size = 16;
  _crypto_key_len = 24;
 }
 else if (_crypto_algo == "aes256-cbc" || _crypto_algo == "aes256-ctr")
 {
  _crypto_block_size = 16;
  _crypto_key_len = 32;
 }
 else if (_crypto_algo == "3des-cbc")
 {
  _crypto_block_size = 8;
  _crypto_key_len = 24;
 }
}

# copied from __base64_code of misc_func.inc
__base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

# helper for base64encode(), copied from base64_code() of misc_func.inc
function _base64_code(c)
{
 return(__base64_chars[c]);
}

# helper for base64encode(), copied from pow2() of misc_func.inc
function _pow2(x)
{
 local_var __ret;

 __ret = 1;
 while(x)
  {
  __ret = __ret * 2;
  x = x  - 1;
  }
 return(__ret);
}

##
# Encodes data into a base64 string
#
# @remark copied from base64() of misc_func.inc
# @param str string to encode
# @return base64 encoded version of "str"
##
function base64encode(str)
{
 local_var len, i, ret, char_count, _bits, val, cnt, mul;

 len = strlen(str);
 i = 0;
 ret = "";
 char_count = 0;
 _bits = 0;
 while(i < len)
 {
  _bits = _bits + ord(str[i]);
  char_count = char_count + 1;
  if(char_count == 3)
  {
    val = _bits / 262144;
    ret = string(ret, _base64_code(c:val));
    val = _bits / 4096;
    val = val & 0x3F;
    ret = string(ret, _base64_code(c:val));
    val = _bits / 64;
    val = val & 0x3F;
    ret = string(ret, _base64_code(c:val));
    val = _bits & 0x3F;
    ret = string(ret, _base64_code(c:val));
    char_count = 0;
    _bits = 0;
 }
 else {
       _bits = _bits * 256;
       }
 i = i + 1;
 }

 if(!(char_count == 0))
 {
  cnt = char_count * 8;
  mul = 16;
  mul = mul - cnt;
  mul = _pow2(x:mul);
  _bits = _bits * mul;
  val = _bits / 262144;
  ret = string(ret, _base64_code(c:val));
  val = _bits / 4096;
  val = val & 0x3F;
  ret = string(ret, _base64_code(c:val));
 if(char_count == 1)
 {
  ret = string(ret, "==");
 }
 else
 {
   val = _bits / 64;
   val = val & 0x3F;
   ret = string(ret, _base64_code(c:val), "=");
  }
 }
 return(ret);
}

#-----------------------------------------------------------------#
# Decode base64 string - ported from public domain code           #
#-----------------------------------------------------------------#
function base64decode(str)
{
 local_var len, i, j, k, ret, base64, b64, a,b,c,o;
 len = strlen(str);
 if (len % 4 != 0) return "";

 ret = "";

 base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

 for (i = 0; i < 256; i++)
   b64[i] = 0;
 for (i = 0; i < strlen(base64); i++)
   b64[ord(base64[i])] = i;

 for(j=0;j<len;j+=4)
 {
   for (i = 0; i < 4; i++)
   {
    c = ord(str[j+i]);
    a[i] = c;
    b[i] = b64[c];
   }

   o[0] = (b[0] << 2) | (b[1] >> 4);
   o[1] = (b[1] << 4) | (b[2] >> 2);
   o[2] = (b[2] << 6) | b[3];
   if (a[2] == ord('='))
     i = 1;
   else if (a[3] == ord('='))
     i = 2;
   else
     i = 3;
   for(k=0;k<i;k++)
      ret += raw_int8(i:o[k]);

   if (i < 3)
     break;
 }

 return ret;
}

#-----------------------------------------------------------------#
# Reads a SSH packet (comes from smb_nt.inc)                      #
#-----------------------------------------------------------------#
function ssh_recv(length)
{
  local_var header, len, trailer, cmpt, payload, ret;

  # longer timeout to account for SSHD on small devices (i.e. IP phones)
  header = recv(socket:_ssh_socket, length:4, min:4,timeout:30);
  if (strlen(header) < 4)return(NULL);
  len = ntol (buffer:header, begin:0);
  if ((len == 0) || (len > max_packet_size)) return(header);
  trailer = recv(socket:_ssh_socket, length:len, min:len);
  if(strlen(trailer) < len )return(NULL);

  seqn_r++;

  # SSH servers can send IGNORE (code 2) or BANNER (code 53) msg
  ret = ord(trailer[1]);
  if ((ret == 2) || (ret == 53))
  {
    if (ret == 53)
      _ssh_banner += getstring (buffer:trailer, pos:2);

    return ssh_recv(length:length);
  }

  return strcat(header, trailer);
}

#-----------------------------------------------------------------#
# Detect if remote ssh server is known to be bugged (SunSSH1.0)   #
#-----------------------------------------------------------------#
function is_sshd_bugged(banner)
{
 if (ereg(string:banner, pattern:"^SSH-2\.0-Sun_SSH_1\.0.*$"))
   return 1;

 return 0;
}

#-----------------------------------------------------------------#
# Waits for the server identification string, and sends our own   #
# identification string.                                          #
#-----------------------------------------------------------------#
function ssh_exchange_identification(login, password, priv)
{
 local_var buf, sshversion, num, prot, client_ver;
 client_ver = kb_ssh_client_ver();

 # Some devices, such as Cisco equipment, can take a while to respond
 # with an entire packet, so we'll be patient here.
 buf = recv_line(socket:_ssh_socket, length:1024, timeout:30);
 if (!buf)
 {
   sleep(1);
   buf = recv_line(socket:_ssh_socket, length:1024);
 }

 if (!buf)
 {
   set_ssh_error(msg: "Nessus did not receive server's version.");
   return 0;
 }
 ssh_log_rawpacket(data:buf,out:FALSE);

 # Cisco fips devices have a tendency to add garbage before
 # the identity string
 if("dcos_sshd run in non-FIPS mode" >< buf )
 {
   buf = recv_line(socket:_ssh_socket, length:1024, timeout:30);

   if (!buf)
   {
     set_ssh_error(msg: "Nessus did not receive server's version.");
     return 0;
   }
   ssh_log_rawpacket(data:buf,out:FALSE);
 }

 # server ident : SSH-%d.%d-servername #
 if (!ereg(string:buf, pattern:"^SSH-*[0-9]\.*[0-9]-*[^\n]"))
 {
   set_ssh_error(msg: "Remote service is not a valid SSH service.");
   return 0;
 }

 sshversion = split(buf, sep:"-", keep:0);
 num = split(sshversion[1], sep:".", keep:0);

 # version supported = 2 & 1.99
 if ( num[0] == 1 && num[1] == 99 )
 {
   if ( ! isnull(priv) )
   {
      if (RSA1_KEY_ID >< priv && defined_func("rsa_public_encrypt") )
      {
        prot = "SSH-1.5-" + client_ver + raw_string(0x0a);
        _ssh_protocol = 1;
      }
      else
      {
        prot = "SSH-2.0-" + client_ver + raw_string(0x0a);
        _ssh_protocol = 2;
      }
   }
   else
   {
     prot = "SSH-2.0-" + client_ver + raw_string(0x0a);
     _ssh_protocol = 2;
   }
 }
 else if ( num[0] == 2 )
 {
  # We use 2.0 protocol
  prot = "SSH-2.0-" + client_ver + raw_string(0x0a);
  _ssh_protocol = 2;
 }
 else if (num[0] == 1 && (num[1] == 33 || num[1] == 5) && defined_func("rsa_public_encrypt"))
 {
  # We use 1.0 protocol
  prot = "SSH-1.5-" + client_ver + raw_string(0x0a);
  _ssh_protocol = 1;
 }
 else
 {
   set_ssh_error(msg: "Nessus < 3.2.1 only supports SSHv2.");
   return 0;
 }

 replace_kb_item(name:"SSH/protocol", value:_ssh_protocol);

 send(socket:_ssh_socket, data:prot);
 ssh_log_rawpacket(data:prot,out:TRUE);

 if (is_sshd_bugged(banner:buf))
 {
   bugged_sshd = 1;
 }

 if ( '\r\n' >< buf ) buf = buf - '\r\n';
   else buf = buf - '\n';

 return buf;
}

#-----------------------------------------------------------------#
# check pattern in buffer                                         #
# return next len in buffer or -1                                 #
#-----------------------------------------------------------------#
function check_pattern(buffer,pattern,length)
{
 local_var alglen, len, alg;

 alglen = ntol (buffer:buffer, begin:length);
 len = length+4+alglen;
 alg = substr(buffer,length+4,len-1);
 if (!ereg(string:alg, pattern:pattern))
  return -1;

 return len;
}

##
# Creates a key exchange packet.
#
# @param code The message code.
# @param payload The contents of the message.
#
# @remark If code is passed in as a integer, it will be converted.
#
# @return A key exchange packet.
##
function kex_packet(code, payload)
{
  local_var len, pad, pad_len;

  if (typeof(code) == "int")
    code = raw_string(code);

  len =
    1 +              # padding length
    1 +              # msg code
    strlen(payload); # payload length

  # padding (mod 8) = 8 - ((len + packet_len(4)) % 8)
  pad_len = 8 - ((len + 4) % 8);

  # If padding len is less than 4, add the block size.
  if (pad_len < 4)
    pad_len += 8;
  len += pad_len;

  pad = crap(data:raw_string(0), length:pad_len);

  return
    raw_int32(i:len) +
    raw_int8(i:pad_len) +
    code +
    payload +
    pad;
}

##
# Compute the HMAC for a packet.
#
# @param data The data to hash.
# @param type The type of packet, server (1) or client (0).
#
# @return The computed HMAC.
##
function mac_compute(data, type)
{
  local_var hash, key;

  if (type == 0)
  {
    data = raw_int32(i:seqn_w) + data;
    key = enc_keys[4];
  }
  else
  {
    data = raw_int32(i:seqn_r) + data;
    key = enc_keys[5];
  }

  if (_mac_algo == "hmac-sha1")
    hash = HMAC_SHA1(data:data, key:key);
  else if (_mac_algo == "hmac-sha2-256")
    hash = HMAC_SHA256(data:data, key:key);
  else if (_mac_algo == "hmac-sha2-512")
    hash = HMAC_SHA512(data:data, key:key);

  return hash;
}

#-----------------------------------------------------------------#
# crypt data                                                      #
#-----------------------------------------------------------------#
function crypt(data)
{
 local_var crypted;

 if ( isnull(data) || isnull(enc_keys) || isnull(enc_keys[2]) || isnull(enc_keys[0]) ) return NULL;
 if ( strlen(data) % _crypto_block_size != 0 )
 {
    data += crap(data:'\0', length:(_crypto_block_size - (strlen(data) % _crypto_block_size) ) );
 }

 if (_crypto_algo == "blowfish-cbc")
   crypted = bf_cbc_encrypt(data:data, key:enc_keys[2], iv:enc_keys[0]);
 else if ("aes" >< _crypto_algo)
 {
  if ( strlen(enc_keys[0]) != 16 && strlen(enc_keys[0]) != 24 && strlen(enc_keys[0]) != 32 ) return NULL;
  if ("cbc" >< _crypto_algo)
    crypted = aes_cbc_encrypt(data:data, key:enc_keys[2], iv:substr(enc_keys[0], 0, 15));
  else
    crypted = aes_ctr_encrypt(data:data, key:enc_keys[2], iv:substr(enc_keys[0], 0, 15));
 }
 else if (_crypto_algo == "3des-cbc")
   crypted = tripledes_cbc_encrypt(data:data, key:enc_keys[2], iv:enc_keys[0]);

 enc_keys[0] = crypted[1];

 return crypted[0];
}

#-----------------------------------------------------------------#
# decrypt data                                                    #
#-----------------------------------------------------------------#
function decrypt(data)
{
 local_var decrypted;

 if ( isnull(data) || isnull(enc_keys) || isnull(enc_keys[3]) || isnull(enc_keys[1]) ) return NULL;
 if ( strlen(data) % _crypto_block_size != 0 )
 {
    data += crap(data:'\0', length:(_crypto_block_size - (strlen(data) % _crypto_block_size )));
 }

 if (_crypto_algo == "blowfish-cbc")
   decrypted = bf_cbc_decrypt(data:data, key:enc_keys[3], iv:enc_keys[1]);
 else if ("aes" >< _crypto_algo)
 {
  if ( strlen(enc_keys[1]) != 16 && strlen(enc_keys[1]) != 24 && strlen(enc_keys[1]) != 32 ) return NULL;
  if ("cbc" >< _crypto_algo)
    decrypted = aes_cbc_decrypt(data:data, key:enc_keys[3], iv:substr(enc_keys[1], 0, 15));
  else
    decrypted = aes_ctr_decrypt(data:data, key:enc_keys[3], iv:substr(enc_keys[1], 0, 15));
 }
 else if (_crypto_algo == "3des-cbc")
   decrypted = tripledes_cbc_decrypt(data:data, key:enc_keys[3], iv:enc_keys[1]);

 enc_keys[1] = decrypted[1];
 return decrypted[0];
}

##
#
# @remark See RFC 4462 for details.
##
function send_ssh_packet(code, payload)
{
  local_var i, len, mac, padding, padding_len, pkt;

  if(code == SSH2_MSG_CHANNEL_DATA || code == SSH2_MSG_CHANNEL_EXTENDED_DATA)
    r_window_size -= strlen(payload);

  # todo - chunk data if payload size exceeds window length

  # Convert integer codes to a byte for convenience.
  if (typeof(code) == "int")
    code = raw_int8(i:code);

  ssh_log_packet(code:code,data:payload,out:TRUE);

  # Calculate the packet's length, including a byte each for padding
  # length and the code.
  len = 1 + 1 + strlen(payload);

  # RFC4253, Section 6
  #
  # Note that the length of the concatenation of 'packet_length',
  # 'padding_length', 'payload', and 'random padding' MUST be a
  # multiple of the cipher block size or 8, whichever is larger.
  #
  # padding (mod 8) = 8 - ((len + packet_len(4)) % 8)
  padding_len = _crypto_block_size - ((len + 4) % _crypto_block_size);

  # RFC4253, Section 6
  #
  # There MUST be at least four bytes of padding.
  if (padding_len < 4)
    padding_len += _crypto_block_size;

  # Add the length of the padding to the overall length of the packet.
  len += padding_len;

  # RFC4253, Section 6
  #
  # The padding SHOULD consist of random bytes.
  padding = "";
  for (i = 0; i < padding_len; i++)
    padding += raw_int8(i:(rand() % 256));

  # Assemble the packet in its intermediate form.
  pkt =
    raw_int32(i:len) +
    raw_int8(i:padding_len) +
    code +
    payload +
    padding;

  # Calculate the MAC over the unencrypted packet.
  mac = mac_compute(data:pkt, type:0);

  # Encrypt the packet, and append MAC.
  pkt = crypt(data:pkt) + mac;

  # Send the packet to the server.
  ssh_log_rawpacket(data:pkt,out:TRUE);
  send(socket:_ssh_socket, data:pkt);


  # Increment the sequence number.
  seqn_w++;
}

#-----------------------------------------------------------------#
# Receive ssh packet                                              #
#-----------------------------------------------------------------#
function recv_ssh_packet(timeout)
{
 local_var len, need, padding_len, full_len, buf, res, macbuf, decrypted;
 local_var hmac, hmacbuf, mac, msg, payload, ret, dbuf;


 if ( isnull(timeout) ) timeout = 120;
 payload = raw_int8(i:0);

 buf = recv(socket:_ssh_socket, length:_crypto_block_size, min:_crypto_block_size, timeout:timeout);
 dbuf = buf;
 if (strlen(buf) != _crypto_block_size)
   return payload;

 decrypted = decrypt(data:buf);

 len = ntol(buffer:decrypted, begin:0);

 # channel not yet open...
 if(isnull(received_size))
 {
   if (len < 0 || len > max_packet_size)
     return payload;
 }
 # channel opened, so compare against window
 else
 {
   if (len < 0 || len > l_window_size)
     return payload;
 }

 need = 4 + len - _crypto_block_size;
 buf = recv(socket:_ssh_socket, length:need, min:need, timeout:timeout);
 if (strlen(buf) != need)
   return payload;

 if (need != 0)
 {
   decrypted = decrypted + decrypt(data:buf);
   dbuf = dbuf + buf;
 }
 ssh_log_rawpacket(data:dbuf,out:FALSE);
 mac = recv(socket:_ssh_socket, length:_mac_len, min:_mac_len, timeout:timeout);
 if (strlen(mac) != _mac_len)
   return payload;
 macbuf = mac_compute(data:decrypted, type:1);

 hmac = hexstr(mac);
 hmacbuf = hexstr(macbuf);
 if (hmac >!< hmacbuf)
   return payload;

 payload = substr(decrypted, 5, strlen(decrypted)-ord(decrypted[4])-1);
 seqn_r++;

 # SSH servers can send IGNORE (code 2) or BANNER (code 53) msg
 ret = ord(payload[0]);
 ssh_log_packet(code:payload[0],data:payload,out:FALSE);
 if (ret == SSH_MSG_IGNORE || ret == SSH_MSG_DEBUG || ret == SSH_MSG_USERAUTH_BANNER)
 {
   if (ret == SSH_MSG_USERAUTH_BANNER)
     _ssh_banner += getstring(buffer:payload, pos:1);

   payload = recv_ssh_packet(timeout:timeout);
   ssh_log_packet(code:payload[0],data:payload,out:FALSE);
   ret = ord(payload[0]);
 }

 if (ret == SSH_MSG_DISCONNECT)
 {
   msg = "The SSH server sent a disconnection message";
   res = getstring(buffer:payload, pos:5);
   if (strlen(res)) msg += " : '" + res + "'";
   msg += " (" + ntol(buffer:payload, begin:1) + ").";

   if (_exit_on_disconnect) exit(1, msg);
   else set_ssh_error(msg:msg);
 }

 return payload;
}

#-----------------------------------------------------------------#
# Get payload from packet                                         #
#-----------------------------------------------------------------#
function packet_payload(packet,code)
{
 local_var packetlen, paddinglen, msgcode, payload;

 packetlen = ntol(buffer:packet, begin:0);
 paddinglen = ord(packet[4]);
 msgcode = ord(packet[5]);

 # Diffie-Hellman Key Exchange Reply
 if (msgcode != code)
  return 0;

 payload = substr(packet,6,packetlen-1);
 return payload;
}

##
# Parses a length-prefixed string from the buffer.
#
# @param buffer Buffer to parse.
# @param pos Position from which to parse.
#
# @return NULL on error, parsed string otherwise.
##
function getstring(buffer, pos)
{
  local_var len;

  if (pos + 4 > strlen(buffer))
    return NULL;

  len = ntol(buffer:buffer, begin:pos);
  if (isnull(len))
    return NULL;

  pos += 4;
  if (pos + len > strlen(buffer))
    return NULL;

  return substr(buffer, pos, pos + len - 1);
}

##
# Creates a variable-length string field for an SSH packet.
#
# @param buffer String to put in field.
#
# @remark The buffer parameter may also be given anonymously.
#
# @return The input string prepended by its 32-bit length.
##
function putstring(buffer)
{
  if (isnull(buffer))
    buffer = _FCT_ANON_ARGS[0];

  return raw_int32(strlen(buffer)) + buffer;
}

##
# Creates a variable-length bignum field for an SSH packet.
#
# @param buffer Bignum to put in field.
#
# @remark The buffer parameter may also be given anonymously.
#
# @return The input string prepended by its 32-bit length.
##
function putbignum(buffer)
{
  local_var len;

  if (isnull(buffer))
    buffer = _FCT_ANON_ARGS[0];

  if (ord(buffer[0]) & 0x80)
    len = raw_int32(strlen(buffer) + 1) + raw_int8(0);
  else
    len = raw_int32(strlen(buffer));

  return len + buffer;
}

#-----------------------------------------------------------------#
# RSA verify signature                                            #
#-----------------------------------------------------------------#
function ssh_rsa_verify(e, n, signature, data)
{
 local_var hash, id_sha1, sigtype, nlen,
  next, tmp_sig, siglen, len, sig,
  hdecoid, hshaoid, hhash, decrypted ;

#comes directly from OpenBSD
 id_sha1 = raw_string(
  0x30, 0x21,
  0x30, 0x09,
  0x06, 0x05,
  0x2b, 0x0e, 0x03, 0x02, 0x1a,
  0x05, 0x00,
  0x04, 0x14
  );

 if (!n)
   return 0;

 sigtype = getstring(buffer:signature, pos:0);
 if (sigtype != "ssh-rsa")
   return 0;

 nlen = strlen(n);
 if (ord(n[0]) == 0)
   nlen--;

 KEY_LEN = nlen * 8;
 # check minimum n size
 if ( (nlen*8) < 512 )
   return 0;

 next = 4 + strlen(sigtype);
 tmp_sig = getstring(buffer:signature,pos:next);
 siglen = strlen(tmp_sig);

 # bad signature (should be less than n)
 if (siglen > nlen)
   return 0;

 # Add padding if needed
 if (siglen < nlen)
 {
   len = nlen - siglen;
   sig = crap(data:raw_string(0x00), length:len) + tmp_sig;
 }
 else
   sig = tmp_sig;

 hash = SHA1(data);

 if (strlen(hash) != 20)
   return 0;

 # must call RSA_public_decrypt from openssl, so convert arg - see ssh-rsa.c
 decrypted = rsa_public_decrypt(sig:sig,e:e,n:n);
 if (!decrypted)
   return 0;

 if (strlen(decrypted) != (strlen(id_sha1)+20))
   return 0;

 hdecoid = hexstr(substr(decrypted,0,strlen(id_sha1)-1));
 hshaoid = hexstr(id_sha1);

 if (hdecoid >!< hshaoid)
   return 0;

 hdecoid = hexstr(substr(decrypted,strlen(id_sha1),strlen(decrypted)-1));
 hhash = hexstr(hash);

 if (hdecoid >!< hhash)
   return 0;

 return 1;
}

#-----------------------------------------------------------------#
# DSA verify signature                                            #
#-----------------------------------------------------------------#
function ssh_dss_verify(p, q, g, pub, signature, data)
{
 local_var sigtype, next, tmp_sig, siglen, r, s, hash;

 sigtype = getstring(buffer:signature, pos:0);
 if (sigtype != "ssh-dss")
   return 0;

 next = 4 + strlen(sigtype);
 tmp_sig = getstring(buffer:signature,pos:next);
 siglen = strlen(tmp_sig);

 r = substr(tmp_sig,  0, 19);
 s = substr(tmp_sig, 20, 39);

 hash = SHA1(data);

 return dsa_do_verify(p:p,g:g,q:q,pub:pub,r:r,s:s,data:hash);
}

##
# Derive the keys for the SSH session.
#
# X is a character, 'A' through 'F', depending on the type of key
# desired (e.g. IV, encryption, MAC).
#
# Derive the key:
#   K[1] = HASH(S || H || X || session_id)
#
# Lengthen the key if required:
#   K[2] = HASH(S || H || K[1])
#   K[3] = HASH(S || H || K[1] || K[2])
#   ...
#   K[N] = HASH(S || H || K[1] || ... || K[N-1])
#
# key = K[1] || ... || K[N]
#
# @remark See RFC 4253 Section 7.2 for details.
#
# @return A list of keys for the current session.
##
function derive_keys(hash, session_id, shared, hash_type)
{
  local_var h, i, k, key, max, s, x;

  if (isnull(hash_type) || (hash_type != "sha1" && hash_type != "sha256"))
  {
    hash_type = "sha1";
  }

  # Convert variables to match formulas.
  h = hash;
  s = putbignum(shared);
  x = ord("A");

  key = make_list();

  # Determine the size of keys that we'll be needing.
  max = _crypto_key_len;
  if (max < _mac_len)
    max = _mac_len;

  for (i = 0; i < 6; i++)
  {
    # Derive the key.
    if (hash_type == "sha1")
      k = SHA1(s + h + raw_int8(x + i) + session_id);
    else if (hash_type == "sha256")
      k = SHA256(s + h + raw_int8(x + i) + session_id);

    # Lengthen the key if required.
    while(strlen(k) < max)
    {
      if (hash_type == "sha1")
        k += SHA1(s + h + k);
      else if (hash_type == "sha256")
        k += SHA256(s + h + k);
    }

    # Truncate the key to only what we need.
    if (i < 4)
      key[i] = substr(k, 0, _crypto_key_len - 1);
    else
      key[i] = substr(k, 0, _mac_len - 1);
  }

  #         MODE OUT  MODE IN
  # enc.iv    0         1
  # enc.key   2         3
  # mac.key   4         5

  return key;
}

#-----------------------------------------------------------------#
# Check is public key is correct                                  #
#-----------------------------------------------------------------#
function dh_valid_key(key, p)
{
 local_var val,i;

 if (ord(key[0]) > 0x80)
   return 0;

 val = 0;
 for(i=0;i<strlen(key);i++)
 {
  val = val + ord(key[i]);
  if (val > 1)
    break;
 }

 # ok if key < p
 if ((val>1) && (bn_cmp(key1:key,key2:p) == -1))
   return 1;

 return 0;
}

#-----------------------------------------------------------------#
# Generate dh public & private keys                              #
#-----------------------------------------------------------------#
function dh_gen_key(p, g)
{
 local_var tries,keys,need;

 dh_pub = dh_priv = "";

 tries = 0;

 if (!p)
   return keys;

 # { "blowfish-cbc", SSH_CIPHER_SSH2, 8, 16, EVP_bf_cbc }
 # hash = sha1 = 20 (len) = 20 * 8 (bits)
 need = 20 * _crypto_block_size;

 # need won't be > than INT_MAX / 2
 # maybe we must test if 2*need >= numbits ...
 #if (need > INT_MAX / 2 || 2 * need >= BN_num_bits(dh->p))
 #  return keys;

 for (tries = 0; tries < 10; tries++)
 {
   dh_priv = bn_random(need:(need*2));
   if (!dh_priv)
     return -1;
   dh_pub = dh_generate_key(p:p, g:g, priv:dh_priv);
   if (!dh_pub)
     return -1;
   if (dh_valid_key(key:dh_pub, p:p))
     break;
 }

 if (tries++ >= 10)
   return -1;

 return 0;
}

##
# Performs cryptographic setup with the SSH server.
#
# @param server_version
# @param nofingerprint
#
# @return 0 on success, -1 on failure.
##
function ssh_kex2(server_version,nofingerprint)
{
  local_var alg, alg_regex, algs, alg_type, ccookie, cinit, client_version;
  local_var codereq, correct, dsa_g, dsa_p, dsa_q, dsa_y, fkey, parsed_host_cert, g;
  local_var hash, hash_type, i, len2, len, msgcode, next, p, pad_len;
  local_var payload, pkt_len, req, res, ret, nonce, rsa_e, rsa_n, scookie;
  local_var shared, signed_h, sinit, start, to_hash, type;

  local_var server_dh_public_key, server_host_key_algo, key_exchange_algo;
  local_var enc_alg_client_to_server, enc_alg_server_to_client;
  local_var mac_alg_client_to_server, mac_alg_server_to_client;
  local_var cmp_alg_client_to_server, cmp_alg_server_to_client;
  local_var server_kex_algo_len, server_kex_algo, kex_algo_supported, kex_algo;

  ### Algorithm Setup ###

  # Algorithms guaranteed to be supported by our implementation.
  key_exchange_algo        = "diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1";
  server_host_key_algo     = "ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,ssh-rsa-cert-v00@openssh.com,ssh-dss-cert-v00@openssh.com,ssh-rsa,ssh-dss";
  enc_alg_client_to_server = "blowfish-cbc";
  mac_alg_client_to_server = "hmac-sha1";
  cmp_alg_client_to_server = "none";

  # Algorithms supported by our implementation if Nessus has them.
  if (defined_func("aes_ctr_encrypt"))
    enc_alg_client_to_server = "aes128-ctr,aes192-ctr,aes256-ctr," + enc_alg_client_to_server;

  if (defined_func("aes_cbc_encrypt"))
    enc_alg_client_to_server = "aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc," + enc_alg_client_to_server;

  if (defined_func("HMAC_SHA256"))
    mac_alg_client_to_server += ",hmac-sha2-256";
  if (defined_func("HMAC_SHA512"))
    mac_alg_client_to_server += ",hmac-sha2-512";

  # We support the same algorithms in both directions.
  enc_alg_server_to_client = enc_alg_client_to_server;
  mac_alg_server_to_client = mac_alg_client_to_server;
  cmp_alg_server_to_client = cmp_alg_client_to_server;

  # We only handle SSHv2, and use the version string from the policy.
  client_version = "SSH-2.0-" + kb_ssh_client_ver();

  ### Key Exchange Message from Server ###

  # Receive message.
  res = ssh_recv(length:2000);
  if (isnull(res))
  {
    set_ssh_error(msg:"ssh_recv failed in ssh_kex2.");
    return -1;
  }
  ssh_log_packet(code:res[5],data:res,out:FALSE);

  # Parse message.
  msgcode = ord(res[5]);
  if (msgcode == SSH_MSG_DISCONNECT)
  {
    set_ssh_error(msg:"SSH key exchange failed. " + get_ssh_error());
    return -1;
  }

  if (msgcode != SSH_MSG_KEXINIT)
  {
    set_ssh_error(msg:"Received code was not SSH_MSG_KEXINIT (" + SSH_MSG_KEXINIT + "). It was : " + msgcode);
    return -1;
  }
  _server_algo = res;

  pkt_len = ntol(buffer:res, begin:0);
  pad_len = ord(res[4]);
  sinit = substr(res, 6, pkt_len + 4 - pad_len - 1);

  # Handle 'cookie' field of SSH_MSG_KEXINIT.
  scookie = substr(res, 6, 6 + 15);

  # Handle 'kex_algorithms' field of SSH_MSG_KEXINIT.
  kex_algo_supported = FALSE;
  foreach kex_algo (split(key_exchange_algo, sep:',', keep:FALSE))
  {
    len = check_pattern(buffer:res, pattern:kex_algo, length:22);
    if (len != -1)
    {
      kex_algo_supported = TRUE;
      break;
    }
  }

  if (!kex_algo_supported)
  {
    server_kex_algo_len = ntol(buffer:res, begin:22);
    server_kex_algo = substr(res, 26, 26 + server_kex_algo_len - 1);
    set_ssh_error(msg:"Unsupported key exchange algorithm : " + server_kex_algo);
    return -1;
  }

  # Handle 'server_host_key_algorithms' field of SSH_MSG_KEXINIT.
  len2 = check_pattern(buffer:res, pattern:"ssh-rsa", length:len);
  if (len2 == -1)
  {
    len2 = check_pattern(buffer:res, pattern:"ssh-dss", length:len);
    if (len2 == -1)
    {
      set_ssh_error(msg:"Remote SSH server does not support DSA and RSA (bugged ?)");
      return -1;
    }
  }

  # Look for an encryption algorithm shared by the client and the
  # server for client-to-server communication.
  algs = split(enc_alg_client_to_server, sep:",", keep:FALSE);

  len = -1;
  foreach alg (algs)
  {
    len = check_pattern(buffer:res, pattern:"(^|,)" + alg, length:len2);
    if (len != -1)
    {
      _crypto_algo = alg;
      break;
    }
  }

  if (len == -1)
  {
    set_ssh_error(msg:"Remote SSH server does not support any of the following encryption"+'\n'+"algorithms for client-to-server communication : " + enc_alg_client_to_server);
    return -1;
  }

  # Look for an encryption algorithm shared by the client and the
  # server for server-to-client communication.
  algs = split(enc_alg_server_to_client, sep:",", keep:FALSE);

  len2 = -1;
  foreach alg (algs)
  {
    len2 = check_pattern(buffer:res, pattern:"(^|,)" + alg, length:len);
    if (len2 != -1)
      break;
  }

  if (len2 == -1)
  {
    set_ssh_error(msg:"Remote SSH server does not support any of the following encryption"+'\n'+"algorithms for server-to-client communication : " + enc_alg_server_to_client);
    return -1;
  }

  # Look for a MAC algorithm shared by the client and the server for
  # client-to-server communication.
  algs = split(mac_alg_client_to_server, sep:",", keep:FALSE);

  len = -1;
  foreach alg (algs)
  {
    alg_regex = alg + "($|,)";
    len = check_pattern(buffer:res, pattern:alg_regex, length:len2);
    if (len != -1)
    {
      _mac_algo = alg;

      if (alg == "hmac-sha1")
        _mac_len = 160 / 8;
      else if (alg == "hmac-sha2-256")
        _mac_len = 256 / 8;
      else if (alg == "hmac-sha2-512")
        _mac_len = 512 / 8;

      break;
    }
  }

  if (len == -1)
  {
    set_ssh_error(msg:"Remote SSH server does not support any of the following MAC algorithms"+'\n'+"for client-to-server communication : " + mac_alg_client_to_server);
    return -1;
  }

  # Look for a MAC algorithm shared by the client and the server for
  # server-to-client communication.
  algs = split(mac_alg_server_to_client, sep:",", keep:FALSE);

  len2 = -1;
  foreach alg (algs)
  {
    len2 = check_pattern(buffer:res, pattern:alg, length:len);
    if (len2 != -1)
      break;
  }

  if (len2 == -1)
  {
    set_ssh_error(msg:"Remote SSH server does not support any of the following MAC algorithms"+'\n'+"for server-to-client communication : " + mac_alg_server_to_client);
    return -1;
  }

  len = check_pattern(buffer:res, pattern:cmp_alg_client_to_server, length:len2);
  if (len == -1)
  {
    set_ssh_error(msg:"Remote SSH server only supports compressed packets but Nessus doesn't.");
    return -1;
  }

  len2 = check_pattern(buffer:res, pattern:cmp_alg_server_to_client, length:len);
  if (len2 == -1)
  {
    set_ssh_error(msg:"Remote SSH server only supports compressed packets but Nessus doesn't.");
    return -1;
  }

  init_crypto_data ();

  ### Key Exchange Message from Client ###

  ccookie = "";
  for (i = 0; i < 16; i++)
    ccookie = ccookie + raw_int8(rand() % 256);

  # Create a SSH_MSG_KEXINIT.
  cinit =
    ccookie +                              # cookie
    putstring(key_exchange_algo) +         # kex_algorithms
    putstring(server_host_key_algo) +      # server_host_key_algorithms
    putstring(enc_alg_client_to_server) +  # encryption_algorithms_client_to_server
    putstring(enc_alg_server_to_client) +  # encryption_algorithms_server_to_client
    putstring(mac_alg_client_to_server) +  # mac_algorithms_client_to_server
    putstring(mac_alg_server_to_client) +  # mac_algorithms_server_to_client
    putstring(cmp_alg_client_to_server) +  # compression_algorithms_client_to_server
    putstring(cmp_alg_server_to_client) +  # compression_algorithms_server_to_client
    raw_int32(0) +                         # languages_client_to_server
    raw_int32(0) +                         # languages_server_to_client
    crap(data:raw_string(0x00), length:5); # payload

  req = kex_packet(payload:cinit, code:SSH_MSG_KEXINIT);
  ssh_log_packet(code:req[5],data:req,out:TRUE);
  send(socket:_ssh_socket, data:req);
  seqn_w++;

  if (kex_algo == 'diffie-hellman-group-exchange-sha1' || kex_algo == 'diffie-hellman-group-exchange-sha256')
  {
    ### Key exchange Request : Diffie-Hellman GEX Request ###

    payload =
      raw_int32(1024) + # minimal size in bits of group
      raw_int32(2048) + # preferred size in bits of group
      raw_int32(8192);  # maximal size in bits of group

    req = kex_packet(payload:payload, code:SSH_MSG_KEXDH_GEX_REQUEST);
    ssh_log_packet(code:req[5],data:req,out:TRUE);
    send(socket:_ssh_socket, data:req);
    seqn_w++;

    ### Key exchange Reply : Diffie-Hellman Key Exchange Reply ###

    res = ssh_recv(length:1000);
    if (isnull(res))
    {
      set_ssh_error(msg:"Connection timed out or was dropped during the key exchange.");
      return -1;
    }
    ssh_log_packet(code:res[5],data:res,out:FALSE);

    payload = packet_payload(packet:res, code:SSH_MSG_KEXDH_REPLY);
    if (!payload)
    {
      set_ssh_error(msg:"Received code was not SSH_MSG_KEXDH_REPLY (" + SSH_MSG_KEXDH_REPLY + ").");
      return -1;
    }

    # get p bignum for dh group
    p = getstring(buffer:payload, pos:0);
    start = 4 + strlen(p);

    if(strlen(p) < (1024 / 8))
    {
      set_ssh_error(msg:"DH modulus received from server (" +
        (strlen(p) * 8) + " bit) is under minimum size.");
      return -1;
    }
    if(strlen(p) > (8192 / 8))
    {
      set_ssh_error(msg:"DH modulus received from server (" +
        (strlen(p) * 8) + " bit) is over maximum size.");
      return -1;
    }

    # get g bignum for dh group
    g = getstring(buffer:payload, pos:start);
  }
  else if (kex_algo == 'diffie-hellman-group1-sha1')
  {
    # RFC2409 section 6.2 (Second Oakley Group)
    # As RFC4253 notes in section 8.1, even though the method has the phrase "group1",
    # it actually uses Oakley Group 2
    p = raw_string(
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
      0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
      0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
      0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
      0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
      0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
      0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
      0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
      0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
      0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
      0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
      0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
      0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
      0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    );

    g = raw_int8(2);
  }
  else if (kex_algo == 'diffie-hellman-group14-sha1')
  {
    # RFC3526 section 3 (2048-bit MODP Group)
    p = raw_string(
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
      0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
      0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
      0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
      0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
      0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
      0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
      0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
      0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
      0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
      0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    );

    g = raw_int8(2);
  }

  # generate public and private keys
  ret = dh_gen_key(p:p, g:g);
  if (ret != 0)
  {
    set_ssh_error(msg:"Error during DH keys generation.");
    return -1;
  }

  ### Diffie Hellman GEX Init ###

  payload = raw_int32(strlen(dh_pub)) + dh_pub;

  if (kex_algo == 'diffie-hellman-group-exchange-sha1' || kex_algo == 'diffie-hellman-group-exchange-sha256')
    codereq = raw_int8(32);
  else
    codereq = raw_int8(30);

  req = kex_packet(payload:payload, code:codereq);
  ssh_log_packet(code:req[5],data:req,out:TRUE);
  send(socket:_ssh_socket, data:req);
  seqn_w++;

  ### Diffie Hellman GEX Reply ###

  res = ssh_recv(length:2000);
  ssh_log_packet(code:res[5],data:res,out:FALSE);
  if (isnull(res))
  {
    set_ssh_error(msg:"Connection timed out or was dropped during the key exchange.");
    return -1;
  }

  if (kex_algo == 'diffie-hellman-group-exchange-sha1' || kex_algo == 'diffie-hellman-group-exchange-sha256')
    codereq = SSH_MSG_KEXDH_GEX_REPLY;
  else
    codereq = SSH_MSG_KEXDH_REPLY;

  payload = packet_payload(packet:res, code:codereq);
  if (!payload)
  {
    set_ssh_error(msg:"Received code was not SSH_MSG_KEXDH_REPLY or SSH_MSG_KEXDH_GEX_REPLY.");
    return -1;
  }

  # server host key blob
  server_host_key_blob = getstring (buffer:payload,pos:0);

  # extract server host key
  alg_type = getstring (buffer:server_host_key_blob, pos:0);
  next = 4 + strlen(alg_type);

  # if this is a host certificate (rather than a host key), verify its signature
  if ('-cert-' >< alg_type)
  {
    server_host_cert_blob = server_host_key_blob;
    parsed_host_cert = parse_ssh_cert(server_host_cert_blob);
    if (isnull(parsed_host_cert))
    {
      set_ssh_error(msg:"Unable to parse "+alg_type+" host certificate.");
      return -1;
    }

    if (parsed_host_cert["signature_type"] !~ "^ssh-(rsa|dss)$")
    {
      set_ssh_error(msg:"Unable to verify signature of "+alg_type+" host certificate ("+parsed_host_cert["signature_type"]+" signatures are currently not supported).");
      return -1;
    }

    if(!verify_ssh_cert_signature(parsed_host_cert))
    {
      set_ssh_error(msg:"Invalid signature on "+alg_type+" host certificate.");
      return -1;
    }
  }

  # unless the caller has explicitly requested not to do host key verification,
  # check the known_hosts file to see if the remote server is trusted
  if (
    (isnull(nofingerprint) || nofingerprint == FALSE) &&
    !check_known_hosts(host_key:server_host_key_blob, host_key_type:alg_type, host_cert:parsed_host_cert)
  )
  {
    return -1;
  }

  # skip over the nonce which is included before e,n/p,q,g,y in v01
  if (
    alg_type == "ssh-rsa-cert-v01@openssh.com" ||
    alg_type == "ssh-dss-cert-v01@openssh.com"
  )
  {
    nonce = getstring (buffer:server_host_key_blob, pos:next);
    next += 4 + strlen(nonce);
  }

  if ("ssh-rsa" >< alg_type)
  {
    type = "rsa";

    rsa_e = getstring (buffer:server_host_key_blob, pos:next);
    next += 4 + strlen(rsa_e);

    rsa_n = getstring (buffer:server_host_key_blob, pos:next);
    next += 4 + strlen(rsa_n);
  }
  else if ("ssh-dss" >< alg_type)
  {
    type = "dsa";

    dsa_p = getstring(buffer:server_host_key_blob, pos:next);
    next += 4 + strlen(dsa_p);

    dsa_q = getstring(buffer:server_host_key_blob, pos:next);
    next += 4 + strlen(dsa_q);

    dsa_g = getstring(buffer:server_host_key_blob, pos:next);
    next += 4 + strlen(dsa_g);

    dsa_y = getstring(buffer:server_host_key_blob, pos:next);
    next += 4 + strlen(dsa_y);
  }
  else
  {
    set_ssh_error(msg:"Server's host keys format is not supported.");
    return -1;
  }

  # Parse the server's Diffie-Hellman public key.
  start = 4 + strlen(server_host_key_blob);
  server_dh_public_key = getstring(buffer:payload, pos:start);

  if (!dh_valid_key(key:server_dh_public_key, p:p))
  {
    set_ssh_error(msg:"Server DH public key is not valid!");
    return -1;
  }

  # Parse the signed hash.
  start += 4 + strlen(server_dh_public_key);
  signed_h = getstring(buffer:payload, pos:start);

  # Calculate the shared secret.
  shared = dh_compute_key(p:p, g:g, dh_server_pub:server_dh_public_key, pub_key:dh_pub, priv_key:dh_priv);
  if (!shared)
  {
    set_ssh_error(msg:"Error during shared secret computing.");
    return -1;
  }

  # hash data
  to_hash =
    putstring(buffer:client_version) +      # client version
    putstring(buffer:server_version) +      # server version
    raw_int32(strlen(cinit) + 1) +          # client cookie (cookie_length, SSH_MSG_KEXINIT, cookie)
    raw_int8(20) +                          #
    cinit +                                 #
    raw_int32(strlen(sinit) + 1) +          # server cookie (cookie length, SSH_MSG_KEXINIT, cookie)
    raw_int8(20) +                          #
    sinit +                                 #
    putstring(buffer:server_host_key_blob); # server host key blob

  if (kex_algo == 'diffie-hellman-group-exchange-sha1' || kex_algo == 'diffie-hellman-group-exchange-sha256')
  {
    to_hash +=
      raw_int32(1024) +     # minimal size in bits of group
      raw_int32(2048) +     # preferred size in bits of group
      raw_int32(8192) +     # maximal size in bits of group
      putbignum(buffer:p) + # p
      putbignum(buffer:g);  # g
  }

  to_hash +=
    putbignum(buffer:dh_pub) +               # public key bignum
    putbignum(buffer:server_dh_public_key) + # server dh public key bignum
    putbignum(buffer:shared);                # shared bignum

  if (kex_algo =~ "-sha1$")
  {
    hash = SHA1(to_hash);
    hash_type = "sha1";
  }
  else if (kex_algo =~ "-sha256$")
  {
    hash = SHA256(to_hash);
    hash_type = "sha256";
  }
  else
  {
    set_ssh_error(msg:"Unsupported key exchange algorithm hash: " + kex_algo);
    return -1;
  }

  if (type == "rsa")
    correct = ssh_rsa_verify(e:rsa_e, n:rsa_n, signature:signed_h, data:hash);
  else if (type == "dsa")
    # Not implemented.
    correct = ssh_dss_verify(p:dsa_p, q:dsa_q, g:dsa_g, pub:dsa_y, signature:signed_h, data:hash);

  if (!correct)
  {
    set_ssh_error(msg:"Server's signature is not valid!");
    return -1;
  }

  session_id = hash;
  enc_keys = derive_keys(hash:hash, shared:shared, session_id:session_id, hash_type:hash_type);

  ### New Key ###

  payload = NULL;

  req = kex_packet(payload:payload, code:SSH_MSG_NEWKEYS);
  ssh_log_packet(code:req[5],data:req,out:FALSE);
  send(socket:_ssh_socket, data:req);
  seqn_w++;

  res = ssh_recv(length:1000);
  ssh_log_packet(code:res[5],data:res,out:FALSE);
  if (isnull(res))
  {
    set_ssh_error(msg:"Connection was dropped or timed out during SSH_MSG_NEWKEYS.");
    return -1;
  }

  payload = packet_payload(packet:res, code:SSH_MSG_NEWKEYS);
  if (!payload)
  {
    set_ssh_error(msg:"Received code was not SSH_MSG_NEWKEYS (" + SSH_MSG_NEWKEYS + ").");
    return -1;
  }

  return 0;
}

##
# Checks if it is okay to connect to this host, according to the known_hosts file
# provided in the policy.
#
# The man page for sshd(8) says known_hosts should consider a host key valid if any of
# the entries in known_hosts match, even if they conflict with other entries. The only
# exception is entries with the @revoked market, which take precedence over all others
#
# Either a host key or a host certificate (parsed by parse_ssh_cert()) should be provided
#
# @param host_key an SSH host key (binary)
# @param host_key_type host key type (e.g., "ssh-rsa", "ssh_dss")
# @param host_cert an SSH host certificate in the format returned by parsed_ssh_cert()
# @return TRUE if it is okay to connect to this host,
#         FALSE otherwise
##
function check_known_hosts(host_key, host_key_type, host_cert)
{
  local_var revoked_key, ca_key, no_ca_match, principal, unknown_principal, fkey;

  # if the server provided a host certificate, extract its public key which is needed for some of the known_hosts-related checks below
  if (host_cert)
  {
    host_key = get_public_key_from_cert(host_cert);
    if (host_cert["key_type"] =~ "^ssh-rsa-")
      host_key_type = "ssh-rsa";
    else if (host_cert["key_type"] =~ "^ssh-dss-")
      host_key_type = "ssh-dss";
  }

  # first, check if the key has been revoked
  foreach revoked_key (get_kb_list("SSH/RevokedKey"))
  {
    revoked_key = base64decode(str:revoked_key);

    # check if the host key itself has been revoked
    if (host_key == revoked_key)
    {
      set_ssh_error(msg:"The host's "+host_key_type+" public key has been revoked in the scan policy's SSH known_hosts file.");
      return FALSE;
    }

    # if a host cert was provided, check if the key of the CA used to sign this host cert has been revoked
    if (host_cert["signature_key"] == revoked_key)
    {
      set_ssh_error(msg:"The public key of the CA used to sign this host's "+host_cert["key_type"]+" certificate has been revoked in the scan policy's SSH known_hosts file.");
      return FALSE;
    }
  }

  # next, check if the key was signed by a trusted CA
  no_ca_match = FALSE;
  unknown_principal = FALSE;
  if (host_cert && !isnull(get_kb_list("SSH/CAKey")))
  {
    foreach ca_key (get_kb_list("SSH/CAKey"))
    {
      ca_key = base64decode(str:ca_key);
      if (host_cert["signature_key"] == ca_key)
      {
        # from http://www.openssh.com/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?rev=1.9;content-type=text%2Fplain :
        # As a special case, a zero-length "valid principals" field means the certificate is valid for
        # any principal of the specified type. 
        if (max_index(host_cert["valid_principals"]) == 0)
          return TRUE;

        foreach principal (host_cert["valid_principals"])
        {
          if (principal == get_host_name() || principal == get_host_ip())
            return TRUE;
        }

        unknown_principal = TRUE;
      }
    }

    no_ca_match = TRUE;
  }

  # lastly, check if the host's key is explicitly listed as trusted
  fkey = get_kb_item("SSH/KnownFingerprint/" + host_key_type);
  if (fkey)
  {
    fkey = base64decode(str:fkey);
    if (host_key != fkey)
    {
      if ("@NOTSET@" >< fkey) set_ssh_error(msg:"The host's "+host_key_type+" public key is missing from the scan policy's SSH known_hosts file.");
      else set_ssh_error(msg:"The host's "+host_key_type+" public key does not match the fingerprint in the scan policy's SSH known_hosts file.");
      return FALSE;
    }
  }
  else if (no_ca_match) # if the CA checking failed _and_ the host's individual key is not trusted
  {
    if (unknown_principal)
    {
      principal = get_host_name();
      if (principal != get_host_ip())
        principal += ', ' + get_host_ip();
      set_ssh_error(msg:"The host's certificate does not contain the following principal(s) : "+principal);
    }
    else
      set_ssh_error(msg:"The host's certificate was not signed by any of the CAs trusted in the"+'\n'+"scan policy's SSH known_hosts file.");
    return FALSE;
  }

  return TRUE;
}

##
# Extracts the public key from an SSH certificate
#
# @anonparam cert SSH certificate (as returned by ssh_parse_cert())
# @return the public key contained in "cert", or
#         NULL the cert uses an unknown/unsupported public key type
##
function get_public_key_from_cert()
{
  local_var cert, key;
  cert = _FCT_ANON_ARGS[0];

  if (cert["key_type"] =~ "^ssh-rsa-")
    key = encode_ssh2_rsa_public_key(e:cert["e"], n:cert["n"]);
  else if (cert["key_type"] =~ "^ssh-dss-")
    key = encode_ssh2_dsa_public_key(p:cert["p"], q:cert["q"], g:cert["g"], y:cert["y"]);
  else
    key = NULL; # unknown/unsupported key type

  return key;
}

##
# Encodes an SSH2 RSA public key
#
# @param e RSA exponent
# @param n RSA public modulus
# @return the encoded public key (in binary format)
##
function encode_ssh2_rsa_public_key(e, n)
{
  local_var key;
  key =
    putstring(buffer:'ssh-rsa') +
    putstring(buffer:e) +
    putstring(buffer:n);
  return key;
}

##
# Encodes an SSH2 DSA public key
#
# @param p DSA parameter as described in FIPS-186-2
# @param q DSA parameter as described in FIPS-186-2
# @param g DSA parameter as described in FIPS-186-2
# @param y DSA parameter as described in FIPS-186-2
# @return the encoded public key (in binary format)
##
function encode_ssh2_dsa_public_key(p, q, g, y)
{
  local_var key;
  key =
    putstring(buffer:'ssh-dss') +
    putstring(buffer:p) +
    putstring(buffer:q) +
    putstring(buffer:g) +
    putstring(buffer:y);
  return key;
}

##
# Decodes/parses an SSH2 public key
#
# @anonparam key the public key to parse (in binary format)
# @return a hash of the decoded public key, or
#         NULL if the operation failed
##
function decode_ssh2_public_key()
{
  local_var key, type;
  key = _FCT_ANON_ARGS[0];
  type = getstring(buffer:key, pos:0);

  if (type == 'ssh-rsa')
    return decode_ssh2_rsa_public_key(key);
  if (type == 'ssh-dss')
    return decode_ssh2_dsa_public_key(key);

  set_ssh_error(msg:"Unable to parse ssh2 public key : type "+type+" is currently unsupported.");
  return NULL; # unknown/unsupported key type
}

##
# Decodes/parses an SSH2 RSA public key
#
# @anonparam key the RSA public key to parse (in binary format)
# @return a hash of the decoded public key, or
#         NULL if the operation failed
##
function decode_ssh2_rsa_public_key()
{
  local_var key, ret, pos;
  key = _FCT_ANON_ARGS[0];
  ret = make_array();
  pos = 0;

  ret["type"] = getstring(buffer:key, pos:pos);
  pos += 4 + strlen(ret["type"]);

  ret["e"] = getstring(buffer:key, pos:pos);
  pos += 4 + strlen(ret["e"]);

  ret["n"] = getstring(buffer:key, pos:pos);

  return ret;
}

##
# Decodes/parses an SSH2 DSA public key
#
# @anonparam key the DSA public key to parse (in binary format)
# @return a hash of the decoded public key, or
#         NULL if the operation failed
##
function decode_ssh2_dsa_public_key()
{
  local_var key, ret, pos;
  key = _FCT_ANON_ARGS[0];
  ret = make_array();
  pos = 0;

  ret["type"] = getstring(buffer:key, pos:pos);
  pos += 4 + strlen(ret["type"]);

  ret["p"] = getstring(buffer:key, pos:pos);
  pos += 4 + strlen(ret["p"]);

  ret["q"] = getstring(buffer:key, pos:pos);
  pos += 4 + strlen(ret["q"]);

  ret["g"] = getstring(buffer:key, pos:pos);
  pos += 4 + strlen(ret["g"]);

  ret["y"] = getstring(buffer:key, pos:pos);

  return ret;
}

##
# Verifies that the signature of the given SSH certificate is valid.
# Currently only RSA and DSA certificates and signatures are supported.
#
# @anonparam cert the certificate that contains the signature to verify (this should be in the format returned by parse_ssh_cert())
# @return TRUE if the signature is valid,
#         FALSE if it is invalid or the cert/signature type is unknown or unsupported
##
function verify_ssh_cert_signature()
{
  local_var cert, data, ca_key;
  cert = _FCT_ANON_ARGS[0];

  if (cert["key_type"] =~ "^ssh-rsa-cert-")
    data = generate_ssh_rsa_cert_sig_data(cert);
  else if (cert["key_type"] =~ "^ssh-dss-cert-")
    data = generate_ssh_dsa_cert_sig_data(cert);
  else
  {
    set_ssh_error(msg:"Unable to verify the certificate signature (type "+cert["key_type"]+" is currently unsupported).");
    return FALSE; # unknown/unsupported cert key type
  }

  ca_key = decode_ssh2_public_key(cert["signature_key"]);
  if (isnull(ca_key)) return FALSE;

  if (ca_key["type"] == "ssh-rsa")
    return ssh_rsa_verify(e:ca_key["e"], n:ca_key["n"], signature:cert["signature"], data:data);
  else if (ca_key["type"] == "ssh-dss")
    return ssh_dss_verify(p:ca_key["p"], q:ca_key["q"], g:ca_key["g"], pub:ca_key["y"], signature:cert["signature"], data:data);

  set_ssh_error(msg:"Unable to verify the certificate signature (CA key type "+ca_key["type"]+" is currently unsupported).");
  return FALSE; # unknown/unsupported CA key type
}

##
# Generates data used to verify the signature in an SSH RSA certificate
#
# @anonparam cert the certificate that contains the signature to verify (this should be in the format returned by parse_ssh_cert())
# @return data used to verify the signature in an SSH RSA certificate
##
function generate_ssh_rsa_cert_sig_data()
{
  local_var cert, data;
  cert = _FCT_ANON_ARGS[0];
  if (isnull(cert)) return NULL;

  if (cert["key_type"] == "ssh-rsa-cert-v00@openssh.com")
  {
    data =
      putstring(cert["key_type"]) +
      putstring(cert["e"]) +
      putstring(cert["n"]) +
      cert["type"] +
      putstring(cert["key_id"]) +
      _encode_string_list(cert["valid_principals"]) +
      cert["valid_after"] +
      cert["valid_before"] +
      putstring(cert["constraints"]) +
      putstring(cert["nonce"]) +
      putstring(cert["reserved"]) +
      putstring(cert["signature_key"]);
  }
  else
  {
    data =
      putstring(cert["key_type"]) +
      putstring(cert["nonce"]) +
      putstring(cert["e"]) +
      putstring(cert["n"]) +
      cert["serial"] +
      cert["type"] +
      putstring(cert["key_id"]) +
      _encode_string_list(cert["valid_principals"]) +
      cert["valid_after"] +
      cert["valid_before"] +
      putstring(cert["critical_options"]) +
      putstring(cert["extensions"]) +
      putstring(cert["reserved"]) +
      putstring(cert["signature_key"]);
  }

  return data;
}

##
# Generates data used to verify the signature in an SSH DSA certificate
#
# @anonparam cert the certificate that contains the signature to verify (this should be in the format returned by parse_ssh_cert())
# @return data used to verify the signature in an SSH DSA certificate
##
function generate_ssh_dsa_cert_sig_data()
{
  local_var cert, data;
  cert = _FCT_ANON_ARGS[0];
  if (isnull(cert)) return NULL;

  if (cert["key_type"] == "ssh-dss-cert-v00@openssh.com")
  {
    data =
      putstring(cert["key_type"]) +
      putstring(cert["p"]) +
      putstring(cert["q"]) +
      putstring(cert["g"]) +
      putstring(cert["y"]) +
      cert["type"] +
      putstring(cert["key_id"]) +
      _encode_string_list(cert["valid_principals"]) +
      cert["valid_after"] +
      cert["valid_before"] +
      putstring(cert["constraints"]) +
      putstring(cert["nonce"]) +
      putstring(cert["reserved"]) +
      putstring(cert["signature_key"]);
  }
  else
  {
    data =
      putstring(cert["key_type"]) +
      putstring(cert["nonce"]) +
      putstring(cert["p"]) +
      putstring(cert["q"]) +
      putstring(cert["g"]) +
      putstring(cert["y"]) +
      cert["serial"] +
      cert["type"] +
      putstring(cert["key_id"]) +
      _encode_string_list(cert["valid_principals"]) +
      cert["valid_after"] +
      cert["valid_before"] +
      putstring(cert["critical_options"]) +
      putstring(cert["extensions"]) +
      putstring(cert["reserved"]) +
      putstring(cert["signature_key"]);
  }

  return data;
}

##
# Parses an SSH certificate.
#
# Currently only RSA and DSA certificates are supported
#
# @anonparam cert certificate to parse (in binary format)
# @return a hash containing the parsed certificate, or
#         NULL if an unknown or unsupported certificate type was provided
##
function parse_ssh_cert()
{
  local_var cert, type;
  cert = _FCT_ANON_ARGS[0];

  type = getstring(buffer:cert, pos:0);
  if ('ssh-rsa-cert' >< type)
    return parse_ssh_rsa_cert(cert);
  if ('ssh-dss-cert' >< type)
    return parse_ssh_dsa_cert(cert);

  set_ssh_error(msg:"Unable to parse certificate (key type "+type+" is currently unsupported).");
  return NULL; # unknown/unsupported certificate type
}

##
# Decodes a string that contains multiple strings.
# Each string is preceded by a 4 byte length, as is the entire list
#
# @anonparam data data to decode (less the leading four byte length of the whole list)
# @return a list of strings
##
function _decode_string_list()
{
  local_var data, total_len, len, strings, string, pos;
  data = _FCT_ANON_ARGS[0];
  strings = make_list();
  if (strlen(data) == 0) return strings;

  total_len = strlen(data);
  pos = 0;
  while (pos < strlen(data))
  {
    string = getstring(buffer:data, pos:pos);
    strings = make_list(strings, string);
    pos += 4 + strlen(string);
  }

  return strings;
}

##
# Encodes a string that is contains multiple strings.
# a 4 byte length is prepended to each string, as well as the entire list
#
# @anonparam strings a list of strings to encode
# @return encoded "strings"
##
function _encode_string_list()
{
  local_var strings, string, data;
  strings = _FCT_ANON_ARGS[0];

  foreach string (strings)
    data += putstring(buffer:string);

  return putstring(buffer:data);
}

##
# Parses an SSH RSA certificate.
#
# @anonparam cert RSA certificate to parse (in binary format)
# @return a hash containing the parsed certificate
##
function parse_ssh_rsa_cert()
{
  local_var cert, ret, pos;
  cert = _FCT_ANON_ARGS[0];
  ret = make_array();
  pos = 0;

  ret["key_type"] = getstring(buffer:cert, pos:pos);
  pos += 4 + strlen(ret["key_type"]);

  if (ret["key_type"] != "ssh-rsa-cert-v00@openssh.com")
  {
    ret["nonce"] = getstring(buffer:cert, pos:pos);
    pos += 4 + strlen(ret["nonce"]);
  }

  ret["e"] = getstring(buffer:cert, pos:pos);
  pos += 4 + strlen(ret["e"]);

  ret["n"] = getstring(buffer:cert, pos:pos);
  pos += 4 + strlen(ret["n"]);

  if (ret["key_type"] != "ssh-rsa-cert-v00@openssh.com")
  {
    ret["serial"] = substr(cert, pos, pos + 7);
    pos += 8;
  }

  ret["type"] = substr(cert, pos, pos + 3);
  pos += 4;

  ret["key_id"] = getstring(buffer:cert, pos:pos);
  pos += 4 + strlen(ret["key_id"]);

  ret["valid_principals"] = getstring(buffer:cert, pos:pos);
  pos += 4 + strlen(ret["valid_principals"]);
  ret["valid_principals"] = _decode_string_list(ret["valid_principals"]);

  ret["valid_after"] = substr(cert, pos, pos + 7);
  pos += 8;

  ret["valid_before"] = substr(cert, pos, pos + 7);
  pos += 8;

  if (ret["key_type"] == "ssh-rsa-cert-v00@openssh.com")
  {
    ret["constraints"] = getstring(buffer:cert, pos:pos);
    pos += 4 + strlen(ret["constraints"]);

    ret["nonce"] = getstring(buffer:cert, pos:pos);
    pos += 4 + strlen(ret["nonce"]);
  }
  else
  {
    ret["critical_options"] = getstring(buffer:cert, pos:pos);
    pos += 4 + strlen(ret["critical_options"]);

    ret["extensions"] = getstring(buffer:cert, pos:pos);
    pos += 4 + strlen(ret["extensions"]);
  }

  ret["reserved"] = getstring(buffer:cert, pos:pos);
  pos += 4 + strlen(ret["reserved"]);

  ret["signature_key"] = getstring(buffer:cert, pos:pos);
  ret["signature_type"] = getstring(buffer:ret["signature_key"], pos:0);
  pos += 4 + strlen(ret["signature_key"]);

  ret["signature"] = getstring(buffer:cert, pos:pos);
  pos += 4 + strlen(ret["signature"]);

  return ret;
}

##
# Parses an SSH DSA certificate.
#
# @anonparam cert DSA certificate to parse (in binary format)
# @return a hash containing the parsed certificate
##
function parse_ssh_dsa_cert()
{
  local_var cert, ret, pos;
  cert = _FCT_ANON_ARGS[0];
  ret = make_array();
  pos = 0;

  ret["key_type"] = getstring(buffer:cert, pos:pos);
  pos += 4 + strlen(ret["key_type"]);

  if (ret["key_type"] != "ssh-dss-cert-v00@openssh.com")
  {
    ret["nonce"] = getstring(buffer:cert, pos:pos);
    pos += 4 + strlen(ret["nonce"]);
  }

  ret["p"] = getstring(buffer:cert, pos:pos);
  pos += 4 + strlen(ret["p"]);

  ret["q"] = getstring(buffer:cert, pos:pos);
  pos += 4 + strlen(ret["q"]);

  ret["g"] = getstring(buffer:cert, pos:pos);
  pos += 4 + strlen(ret["g"]);

  ret["y"] = getstring(buffer:cert, pos:pos);
  pos += 4 + strlen(ret["y"]);

  if (ret["key_type"] != "ssh-dss-cert-v00@openssh.com")
  {
    ret["serial"] = substr(cert, pos, pos + 7);
    pos += 8;
  }

  ret["type"] = substr(cert, pos, pos + 3);
  pos += 4;

  ret["key_id"] = getstring(buffer:cert, pos:pos);
  pos += 4 + strlen(ret["key_id"]);

  ret["valid_principals"] = getstring(buffer:cert, pos:pos);
  pos += 4 + strlen(ret["valid_principals"]);
  ret["valid_principals"] = _decode_string_list(ret["valid_principals"]);

  ret["valid_after"] = substr(cert, pos, pos + 7);
  pos += 8;

  ret["valid_before"] = substr(cert, pos, pos + 7);
  pos += 8;

  if (ret["key_type"] == "ssh-dss-cert-v00@openssh.com")
  {
    ret["constraints"] = getstring(buffer:cert, pos:pos);
    pos += 4 + strlen(ret["constraints"]);

    ret["nonce"] = getstring(buffer:cert, pos:pos);
    pos += 4 + strlen(ret["nonce"]);
  }
  else
  {
    ret["critical_options"] = getstring(buffer:cert, pos:pos);
    pos += 4 + strlen(ret["critical_options"]);

    ret["extensions"] = getstring(buffer:cert, pos:pos);
    pos += 4 + strlen(ret["extensions"]);
  }

  ret["reserved"] = getstring(buffer:cert, pos:pos);
  pos += 4 + strlen(ret["reserved"]);

  ret["signature_key"] = getstring(buffer:cert, pos:pos);
  ret["signature_type"] = getstring(buffer:ret["signature_key"], pos:0);
  pos += 4 + strlen(ret["signature_key"]);

  ret["signature"] = getstring(buffer:cert, pos:pos);
  pos += 4 + strlen(ret["signature"]);

  return ret;
}

##
# Check if a service is supported.
#
# @anonparam name Name of service to check.
#
# @return Boolean indicating whether a service is supported.
##
function ssh_req_svc()
{
  local_var code, svc, payload, res;

  # Process arguments.
  svc = _FCT_ANON_ARGS[0];

  # Request service from server.
  payload = putstring(buffer:svc);
  send_ssh_packet(code:SSH_MSG_SERVICE_REQUEST, payload:payload);

  # Read response from server.
  res = recv_ssh_packet();
  code = ord(res[0]);

  if (code != SSH_MSG_SERVICE_ACCEPT)
  {
    set_ssh_error(msg:"Server does not support the " + svc + " service. Received code was : " + code + ".");
    return FALSE;
  }

  return TRUE;
}

##
# Check if an authentication method is supported.
#
# @anonparam method Method to check.
# @anonparam user User to check the methods for.
#
# @return TRUE if authentication method is supported, 
#         FALSE if authentication method is not supported,
#         NULL if no auth methods are supported,
#         SSH_MSG_USERAUTH_SUCCESS if authentication as user succeeded.
##
function ssh_auth_supported(method, user)
{
  local_var code, payload, rc, res;

  if (_ssh_supported_authentication == "")
  {
    # Request a list of supported authentication methods.
    payload =
      putstring(buffer:user) +
      putstring(buffer:"ssh-connection") +
      putstring(buffer:"none");
    send_ssh_packet(code:SSH_MSG_USERAUTH_REQUEST, payload:payload);

    # Receive response.
    res = recv_ssh_packet();
    code = ord(res[0]);

    if (code == SSH_MSG_USERAUTH_SUCCESS)
    {
      _ssh_supported_authentication = getstring(buffer:res, pos:1);
      if (!_ssh_supported_authentication) 
        _ssh_supported_authentication = "none";

      return SSH_MSG_USERAUTH_SUCCESS;
    }

    if (code != SSH_MSG_USERAUTH_FAILURE)
    {
      set_ssh_error(msg:"Server did not reject the 'none' authentication method. Received code was : " + code + ".");
      return NULL;
    }

    _ssh_supported_authentication = getstring(buffer:res, pos:1);

    # If not method was given, storing the list of supported methods is
    # enough.
    if (isnull(method))
      return TRUE;
  }

  rc = (method >< _ssh_supported_authentication);
  if (!rc)
    set_ssh_error(msg:"Error : Remote server does not support the '" + method + "' authentication method. It supports : " + _ssh_supported_authentication + ".");
  else
    set_ssh_error(msg:NULL);

  return rc;
}

##
# Attempt authentication over SSHv2.
#
# @remark See RFC 4252 for details.
#
# @param cert Certificate with public key, signed by CA key.
# @param host Hostname for kerberos.
# @param password Password to attempt to log in with.
# @param pub Public key or certificate.
# @param priv Private key, possibly encrypted.
# @param passphrase Passphrase to decrypt private key.
# @param realm Kerberos realm
# @param user Username to attempt to log in with.
#
# remark ssh_auth_none() is tried only if the "/tmp/ssh/try_none" KB item is set.
#
# @return True if successful, false otherwise.
##
function ssh_userauth2(cert, host, password, pub, priv, passphrase, realm, user)
{
  local_var msg;

  # Sanity check arguments.
  if (isnull(user))
    return FALSE;

  # Check if user authentication is supported.
  if (!ssh_req_svc("ssh-userauth"))
    return FALSE;

  # If the server supports authentication without credentials, we're done.
  if (ssh_auth_supported(user:user) == SSH_MSG_USERAUTH_SUCCESS)
  {
    if (strlen(password) == 0 && isnull(priv) && isnull(pub) && isnull(cert)) return TRUE;
  }

  # Check if we have the information necessary to log in using GSSAPI.
  if (password && realm)
  {
    if (!ssh_auth_supported(method:"gssapi-with-mic"))
    {
      # in Nessus 6 the user will explicitly state they want to use Kerberos auth, in which case this should not fail silently
      if (defined_func("nasl_level") && nasl_level() >= 6000)
      {
        msg = 'The remote SSH server does not appear to support Kerberos authentication.'; 
        set_ssh_error(msg:msg);
      }

      return FALSE;
    }

    return ssh_auth_gssapi(user:user, password:password, realm:realm, host:host);
  }

  # Check if we have the information necessary to log in using public
  # keys. in nessus >= 6 only a private key is required
  if (priv && (cert || pub || (defined_func('nasl_level') && nasl_level() >= 6000)))
  {
    if (!ssh_auth_supported(method:"publickey"))
      return FALSE;

    # Try authentication with a certificate.
    if (cert)
    {
    if (ssh_auth_publickey(
      pub        : cert,
      priv       : priv,
      passphrase : passphrase,
      user       : user
    )) return TRUE;
    }

    # Try authentication with a public key. In Nessus 6 or later, only the private key is needed.
    if (ssh_auth_publickey(
      pub        : pub,
      priv       : priv,
      passphrase : passphrase,
      user       : user
    )) return TRUE;

    msg = get_ssh_error();
    if (!msg) msg = "Public key authentication failed.";

    if (password)
    {
      msg += '
It seems you provided both certificates / keys and password.
In this case Nessus only uses your certificates / keys.
Nessus did not try both. As password authentication is
vulnerable to Man-in-the-Middle attacks, that implies your keys
are useless (a "malicious server" will just reject your public
key authentication and accept any provided password).
';
    }
    set_ssh_error(msg:msg);

    return FALSE;
  }

  # Check if we have the information necessary to log in using a
  # password.
  if (!isnull(password))
  {
    # Try both keyboard-interactive and password authentication methods.
    #
    # VMWare ESX < 4 claims to support kb-interactive, but does not,
    # several badly configured OSes will not support 'password' but
    # will support 'keyboard-interactive'.
    #
    # The strategy is to prefer keyboard-interactive, and fallback to
    # password if that fails.
    if (ssh_auth_supported(method:"keyboard-interactive"))
    {
      if (ssh_auth_keyboard(user:user, password:password)) return TRUE;
      if ("must be changed" >< get_ssh_error()) return FALSE;
    }

    if (ssh_auth_supported(method:"password") && ssh_auth_password(user:user, password:password))
      return TRUE;

    if (ssh_auth_supported(method:"none") && get_kb_item("/tmp/ssh/try_none") && ssh_auth_none(user:user, password:password))
      return TRUE;

    msg = get_ssh_error();
    if (
      ssh_auth_supported(method:"keyboard-interactive") ||
      ssh_auth_supported(method:"password") ||
      (ssh_auth_supported(method:"none") && get_kb_item("/tmp/ssh/try_none"))
    )
    {
      if (
        get_kb_item("/tmp/ssh/try_none") &&
        "Remote server does not support the 'none' authentication method" >< msg
      ) set_ssh_error(msg:"Failed to authenticate using the supplied password.");
      else set_ssh_error(msg:"Failed to authenticate using the supplied password. " + msg);
    }
    else set_ssh_error(msg:"Failed to authenticate using the supplied credentials.");

    return FALSE;
  }

  # We only get here if we don't have the credentials necessary to try
  # any authentication method.
  set_ssh_error(msg:"Nessus needs public and private keys, private keys and certificates, or a password.");
  return FALSE;
}

#-----------------------------------------------------------------#
# Open channel                                                    #
#-----------------------------------------------------------------#
function ssh_open_channel()
{
 local_var payload, i, soc, ret, val;

 if (bugged_sshd && !bugged_first)
 {
   local_channel++;

   l_window_size = initial_window_size;
   remote_channel = bugged_channels[local_channel];
   r_window_size = bugged_rws[local_channel];
   r_packet_size = bugged_rps[local_channel];
   return 0;
 }

 local_channel++;

 # session = "session"
 # initial window size = 32768
 # maximum packet size = 32768
 l_window_size = initial_window_size;
 payload = putstring(buffer:"session") + raw_int32(i:local_channel) +
           raw_int32(i:initial_window_size) + raw_int32(i:max_packet_size);

 # SSH_MSG_CHANNEL_OPEN == 90
 send_ssh_packet(payload:payload, code:raw_int8(i:90));

 # SSH_MSG_CHANNEL_OPEN_CONFIRMATION == 91 (92 == failure)
 payload = recv_ssh_packet();

 # Fix for tectia AIX
 if (ord(payload[0]) == SSH2_MSG_CHANNEL_EXTENDED_DATA)
 {
   payload = getstring(buffer:payload, pos:9);
   _ssh_cmd_error += payload;
   val = update_window_size(size:strlen(payload));
   if (val == 0)
      payload = recv_ssh_packet();
 }

 # Fix for SSH host key exchange extension
 if (ord(payload[0]) == SSH_MSG_GLOBAL_REQUEST)
 {
   if ("hostkeys-00@openssh.com" >< payload || "hostkeys-prove-00@openssh.com" >< payload)
   {
     payload = putstring(buffer:"session") + raw_int32(i:local_channel) +
               raw_int32(i:initial_window_size) + raw_int32(i:max_packet_size);

     send_ssh_packet(payload:payload, code:raw_int8(i:90));

     payload = recv_ssh_packet();
   }
   else
   {
     set_ssh_error(msg:"We received an unknown SSH_MSG_GLOBAL_REQUEST when opening the channel.");
   }
 }

 if (ord(payload[0]) == SSH_MSG_DISCONNECT)
 {
   set_ssh_error(msg:"SSH open channel request failed. " + get_ssh_error());
   return -1;
 }
 else if (ord(payload[0]) == SSH2_MSG_CHANNEL_OPEN_FAILURE)
 {
   ret = "SSH open channel request failed";
   val = getstring(buffer:payload, pos:9);
   if (strlen(val)) ret += " : '" + val + "'";
   ret += " (reason code " + ntol(buffer:payload, begin:5) + ").";

   set_ssh_error(msg:ret);
   return -1;
 }
 else if (ord(payload[0]) != SSH2_MSG_CHANNEL_OPEN_CONFIRMATION)
 {
   set_ssh_error(msg:string("Received code was not SSH_MSG_CHANNEL_OPEN_CONFIRMATION (91). It was : " , ord(payload[0])));
   return -1;
 }

 received_size = 0;
 remote_channel = ntol(buffer:payload, begin:5);
 r_window_size = ntol(buffer:payload, begin:9);
 r_packet_size = ntol(buffer:payload, begin:13);

 # For bugged channel like Sun_SSH_1.0 we create 10 channels at startup
 # Sun_SSH supports only 10 channels at the same time.
 if (bugged_sshd)
 {
   bugged_first = 0;
   bugged_channels = bugged_rws = bugged_rps = NULL;
   bugged_channels[0] = 0;
   bugged_rws[0] = 0;
   bugged_rps[0] = 0;
   bugged_channels[local_channel] = remote_channel;
   bugged_rws[local_channel] = r_window_size;
   bugged_rps[local_channel] = r_packet_size;
   for (i=local_channel+1; i < 11; i++)
   {
      payload = putstring(buffer:"session") + raw_int32(i:i) +
                raw_int32(i:initial_window_size) + raw_int32(i:max_packet_size);

      send_ssh_packet(payload:payload, code:raw_int8(i:90));

      payload = recv_ssh_packet();
      if (ord(payload[0]) == SSH_MSG_DISCONNECT)
      {
        set_ssh_error(msg:"SSH open channel request failed. " + get_ssh_error());
        return -1;
      }
      else if (ord(payload[0]) == SSH2_MSG_CHANNEL_OPEN_FAILURE)
      {
        ret = "SSH open channel request failed";
        val = getstring(buffer:payload, pos:9);
        if (strlen(val)) ret += " : '" + val + "'";
        ret += " (reason code " + ntol(buffer:payload, begin:5) + ").";

        set_ssh_error(msg:ret);
        return -1;
      }
      else if (ord(payload[0]) != SSH2_MSG_CHANNEL_OPEN_CONFIRMATION)
      {
        set_ssh_error(msg:string("Received code was not SSH_MSG_CHANNEL_OPEN_CONFIRMATION (91). It was : " , ord(payload[0])));
        return -1;
      }

      bugged_channels[i] = ntol(buffer:payload, begin:5);
      bugged_rws[i] = ntol(buffer:payload, begin:9);
      bugged_rps[i] = ntol(buffer:payload, begin:13);

   }
 }

 # all is ok, user is authenticated
 return 0;

}

#-----------------------------------------------------------------#
# Close channel                                                   #
#-----------------------------------------------------------------#
function ssh_close_channel(end)
{
 local_var iter, p, payload, timeout;

 # session = "session"
 # sender channel = 4444  / should we try different number on failure ?
 # initial window size = 32768
 # maximum packet size = 32768
 payload = raw_int32(i:remote_channel);

 # SSH_MSG_CHANNEL_CLOSE == 97
 send_ssh_packet(payload:payload, code:raw_int8(i:97));

 if (!end)
 {
   p = _ssh_current_port;
   if (!p) p = 0;

   # SSH_MSG_CHANNEL_CLOSE == 97
   if ("Cisco-" >< get_ssh_server_version()) timeout = 15;
   else timeout = NULL;

   payload = recv_ssh_packet(timeout:timeout);
   if (
     strlen(payload) == 0 ||
     (strlen(payload) == 1 && ord(payload[0]) == 0)
   ) return 0;

   if (
     SONICWALL_SSH ||
     get_kb_item("SSH/"+p+"/close_channel_looping")
   ) return 0;

   iter = 0;
   while((ord(payload[0]) != SSH2_MSG_CHANNEL_CLOSE) && (ord(payload[0]) != 0))
   {
    iter++;

    # nb: recv_buffer is intended to be global to capture any remaining command output in 'ssh_cmd()'.
    if (ord(payload[0]) == SSH2_MSG_CHANNEL_DATA)
    {
      recv_buffer += remove_escape_sequences(getstring(buffer:payload, pos:5));
    }

     payload = recv_ssh_packet();
     if (
       strlen(payload) == 0 ||
       (strlen(payload) == 1 && ord(payload[0]) == 0)
     ) return 0;

     if (ord(payload[0]) == SSH2_MSG_CHANNEL_REQUEST)
     {
       payload = getstring(buffer:payload, pos:5);
       if ("keepalive@openssh.com" >< payload && iter > 3)
       {
         replace_kb_item(name:"SSH/"+p+"/close_channel_looping", value:iter);
         return 0;
       }
     }

     # nb: hosts may be slow to return output when closing a channel -- keep this number high.
     if (iter > 100000)
     {
       replace_kb_item(name:"SSH/"+p+"/close_channel_looping", value:iter);
       return 0;
     }
   }
 }

 received_size = NULL;
 # all is ok, user is authenticated
 return 0;

}

##
# Request an SSH channel.
#
# @param s Name of channel.
# @extra extra Any extra arguments, appended as a string to the payload.
# @param [want_reply]:boolean] TRUE if responses should be validated, FALSE otherwise.
#
# @return 1 on success, 0 on failure.
##
function ssh_request_channel(s, extra, want_reply)
{
  local_var iter, payload, val;

  payload = raw_int32(i:remote_channel) + putstring(buffer:s) + raw_int8(i:_ssh_want_reply);
  if (!isnull(extra)) payload += extra;
  send_ssh_packet(payload:payload, code:raw_int8(i:SSH2_MSG_CHANNEL_REQUEST));

  if (want_reply)
  {
    payload = recv_ssh_packet();

    iter = 0;
    while (ord(payload[0]) == SSH2_MSG_CHANNEL_WINDOW_ADJUST || ord(payload[0]) == SSH2_MSG_CHANNEL_REQUEST)
    {
      if (iter++ > 5) break;

      if (ord(payload[0]) == SSH2_MSG_CHANNEL_WINDOW_ADJUST)
      {
        payload = ntol(buffer:payload, begin:5);
        r_window_size += payload;
      }

      payload = recv_ssh_packet();
    }

    if (ord(payload[0]) != SSH2_MSG_CHANNEL_SUCCESS) return 0;
  }

  return 1;

}

##
# Request an SSH subsystem.
#
# @param subsystem Name of subsystem; eg, "sftp".
# @param [want_reply]:boolean] TRUE if responses should be validated, FALSE otherwise.
#
# @return 1 on success, 0 on failure, same as 'ssh_request_channel()'.
##
function ssh_request_subsystem(subsystem, want_reply)
{
  return ssh_request_channel(s:"subsystem", want_reply:want_reply, extra:putstring(buffer:subsystem));
}

#-----------------------------------------------------------------#
# Login to SSH server                                             #
#-----------------------------------------------------------------#
function ssh_login(login, password, pub, priv, passphrase, realm, host, nofingerprint, cert)
{
 local_var ret, server_version;

 init();

 _ssh_current_user = login;

 # Exchange protocol version identification strings with the server.
 server_version = ssh_exchange_identification(login:login, password:password, priv:priv);

 if (!server_version)
  return -1;

 _ssh_server_version = server_version;

 if (_ssh_protocol == 2)
 {
  # key exchange
  ret = ssh_kex2(server_version:server_version, nofingerprint:nofingerprint);
  if (ret != 0)
    return -1;

  # Authenticate user.
  ret = ssh_userauth2(
    host       : host,
    user       : login,
    password   : password,
    pub        : pub,
    priv       : priv,
    passphrase : passphrase,
    realm      : realm,
    cert       : cert
  );
  if (!ret)
    return -1;
 }
 else
 {
  # key exchange
  ret = ssh_kex1(nofingerprint:nofingerprint);
  if (ret != 0)
    return -1;

  ret = ssh_userauth1(login:login, password:password, priv:priv, passphrase:passphrase);
  if (ret != 0)
    return -1;
 }

 # all is ok
 return 0;
}

#-----------------------------------------------------------------#
# Return size we can send on the channel and in the packet        #
#-----------------------------------------------------------------#
function get_data_size()
{
 local_var len;

 if (r_window_size <= r_packet_size)
    len = r_window_size;
 else
    len = r_packet_size;

 # packet option ~= 50 bytes
 len -= 50;

 # Remote server has not readjusted his window
 if (len <= 0)
    return -1;

 return len;
}

#-----------------------------------------------------------------#
# Update Window channel size on SSH server                        #
#-----------------------------------------------------------------#
function update_window_size(size)
{
 local_var len, payload;
 l_window_size -= size;
 received_size += size;

 # Maximum allocated memory is 20 MB
 # A correct server will send 32768 bytes packet. So we stop before
 # to get data.
 # A non standard server will just be stopped by nessusd.
 if (received_size > 19000000)
   return -1;

 if (l_window_size < (window_base / 2))
 {
   len = window_base - l_window_size;
   payload = raw_int32(i:remote_channel) + raw_int32(i:len);

   # SSH_MSG_CHANNEL_WINDOW_ADJUST == 93
   send_ssh_packet( payload:payload, code:raw_int8(i:93));

   l_window_size += len;
 }

 return 0;
}

function is_password_prompt()
{
 local_var buf;
 buf = _FCT_ANON_ARGS[0];
 if ( strlen(buf) < strlen("password:") ) return FALSE;
 if ( tolower(substr(buf, strlen(buf) - strlen("password:"), strlen(buf) - 1 )) == "password:" ) return TRUE;
 if ( strlen(buf) < strlen("password: ") ) return FALSE;
 if ( tolower(substr(buf, strlen(buf) - strlen("password: "), strlen(buf) - 1 )) == "password: " ) return TRUE;
 return FALSE;
}

##
# Executes a command through the SSH service.
#
# @param cmd     Command to run.
# @param timeout Read timeout
# @param nosudo  Do not use sudo to elevate privileges.
# @param nosh    Do not run command through 'sh'.
# @param noexec  Do not run the command directly but use a shell instead.
# @param cisco   Target behaves like Cisco IOS or similar.
# @param nosetup Do not open a channel or send a pty-req.
# @param noclose Do not close the channel when done. LEAVES CHANNEL OPEN.
#                To be followed by a command with nosetup:TRUE. You must
#                close the channel either with a subsequent ssh_cmd() or
#                by calling ssh_close_channel().
# @param no53    If FALSE send the TTY ECHO (code 53) parameter with a 0
#                value, if TRUE do not send TTY ECHO parameter at all
#                some SSH implementations (Palo Alto) do like this set 
#                at all. Defaults to TRUE (established behavior)
#                sent in the pty-req packet
# @param term    String containing the TERM environmental variable
#                defaults to vt100, sent in the pty-req packet
# @return True if successful, false otherwise.
##
function ssh_cmd(cmd,timeout,nosudo, nosh, noexec, cisco, nosetup, last5_prompt, noclose, term, no53, allow_aos)
{
 local_var payload, ret, tempbuf, ltempbuf, end, cret, val, dbegin, dend, derror, spass, su_sudo_pass;
 local_var su, supass, supath, last, last5;
 local_var code_begin, code_end, code_error;
 local_var envvars, m;
 local_var does_echo;
 local_var sent_dbegin;
 local_var cmdd, sub1, sub2;
 local_var sulogin;
 local_var root;
 local_var line, cmd_prompt, pagination_prompt;
 local_var enable_pass;
 local_var want_reply, iter, keepalives;
 local_var ttymodes;
 local_var cisco_is_paging, cisco_ltempbuf;

 if(AOS_SSH && !allow_aos) return FALSE;
 if(AOS_SSH) noclose = TRUE;

 if (isnull(no53)) no53 = FALSE;

 if (isnull(term)) term = "vt100";

 if (isnull(last5_prompt)) last5_prompt = FALSE;

 does_echo = 0;
 if ( isnull(nosudo)  || nosudo == FALSE )
 {
   su = get_kb_item("Secret/SSH/sudo");
   sulogin = get_kb_item("Secret/SSH/su-login");
   supass = get_kb_item("Secret/SSH/sudo-password");

   supath = get_kb_item("Secret/SSH/sudo_path");
   if (isnull(supath)) supath = "";

   root = get_kb_item("Secret/SSH/root");
   if (isnull(root)) root = "root";
 }
 if (cisco) enable_pass = get_kb_item("Secret/SSH/enable-password");

 if ( ! su && ( isnull(nosh) || nosh == FALSE ) )
  cmd = 'sh -c \'' + str_replace(find:"'", replace:"'\''", string:cmd) + '\'';

 if (!isnull(su) && su != SU_NONE)
 {
  code_begin = rand() % 1073741824;
  while ( ( code_end = ( rand() % 1073741824 )) == code_begin ) ;
  while ( ( code_error = ( rand() % 1073741824)  ) == code_begin || code_error == code_end) ;

  sent_dbegin = dbegin = string("nessus_su_`echo ", code_begin, "`");
  dend   = string("nessus_su_`echo ", code_end, "`");
  derror = string("nessus_su_`echo ", code_error, "`");

  cmd = strcat('\'echo ', dbegin, ' ; ', str_replace(find:"'", replace:"'\''", string:cmd), '; echo ', dend, '\' || echo ', derror, '\n');

  if (envvars) cmd = strcat(envvars, " ", cmd);

  if (su == SU_DZDO) cmd = strcat('sh -c ', cmd);
  else if (su == SU_PBRUN) cmd = strcat('sh -c ', cmd);
  else cmd = strcat('-c ', cmd);

  if (su == SU_SUDO)
    cmd = string(supath, 'sudo -u ', root, ' -p Password: sh ', cmd);
  else if (su == SU_SU)
    cmd = string(supath, 'su ', root, ' ', cmd);
  else if (su == SU_SU_AND_SUDO && ! isnull(sulogin) )
    cmd = string(supath, 'su ', sulogin, ' -c "', supath, 'sudo -u ', root, ' -p Password: sh ', chomp(cmd), '"\n');
  else if (su == SU_DZDO)
    cmd = string(supath, 'dzdo -u ', root, ' -p Password: ', cmd);
  else if (su == SU_PBRUN)
    cmd = string(supath, 'pbrun -u ', root, ' ', cmd);

  cmd = 'stty raw -echo\n' + cmd;

  dbegin = "nessus_su_" + code_begin;
  dend = "nessus_su_" + code_end;
  derror = "nessus_su_" + code_error;
 }

 # Flash error buffer
 _ssh_cmd_error = "";
 if (_ssh_protocol == 1)
 {
   local_var result;
   result = ssh_cmd1(cmd:cmd, timeout:timeout, su:su, supass:supass, dbegin:dbegin, dend:dend, derror:derror, sent_dbegin:sent_dbegin, noexec:noexec, cisco:cisco, enable_pass:enable_pass);
   ssh_log_command_and_response(command: cmd, response: result);
   return result;
 }

 # Open channel
 if (!nosetup)
  {
   ret = ssh_open_channel();
   if (ret != 0)
   {
     _ssh_cmd_error = "Nessus failed to open a new SSH channel. " + get_ssh_error();
     return NULL;
   }
  }

 # ssh_putenv(key:"LANG", value:"C");

 if ((isnull(su) || su == SU_NONE) && !noexec && !nosetup && !cisco)
 {
  su = NULL;
  payload = raw_int32(i:remote_channel) + putstring(buffer:"exec") + raw_int8(i:0) +
            putstring(buffer:cmd);

  # SSH_MSG_CHANNEL_REQUEST == 98
  send_ssh_packet(payload:payload, code:raw_int8(i:98));
 }
 else if (nosetup)
 {
   cmd_prompt = get_kb_item("/tmp/ssh_cmd/cmd_prompt");

   payload = raw_int32(i:remote_channel) + putstring(buffer:cmd+'\n');
   send_ssh_packet(payload:payload, code:raw_int8(i:94));
 }
 else
 {
  spass = 0;
  su_sudo_pass = 0;
  if(!no53) ttymodes = raw_int8(i:53) + raw_int32(i:0);
  ttymodes += raw_int8(i:72) + raw_int32(i:0) + raw_int8(i:0);
  payload = raw_int32(i:remote_channel) + putstring(buffer:"pty-req") + raw_int8(i:0) +
            putstring(buffer:term) + raw_int32(i:80) + raw_int32(i:24) + raw_int32(i:640) + raw_int32(i:480) +
            putstring(buffer:ttymodes);

  # SSH_MSG_CHANNEL_REQUEST == 98
  send_ssh_packet(payload:payload, code:raw_int8(i:98));

  payload = raw_int32(i:remote_channel) + putstring(buffer:"shell") + raw_int8(i:0) ;

  # SSH_MSG_CHANNEL_REQUEST == 98
  send_ssh_packet(payload:payload, code:raw_int8(i:98));
 }


 recv_buffer = NULL;

 # SSH_MSG_CHANNEL_SUCCESS == 99
 # while for previous useless messages (SSH_MSG_CHANNEL_WINDOW_ADJUST, ...)
 payload = recv_ssh_packet(timeout:timeout);

 iter = 0;
 keepalives = 0;
 while(ord(payload[0]) == SSH2_MSG_CHANNEL_WINDOW_ADJUST || ord(payload[0]) == SSH2_MSG_CHANNEL_EXTENDED_DATA || ord(payload[0]) == SSH2_MSG_CHANNEL_REQUEST)
 {
  if (iter++ > 5) break;
  if (ord(payload[0]) == SSH2_MSG_CHANNEL_WINDOW_ADJUST)
  {
    payload = ntol(buffer:payload, begin:5);
    r_window_size += payload;
  }
  else if (ord(payload[0]) == SSH2_MSG_CHANNEL_EXTENDED_DATA)
  {
    payload = getstring(buffer:payload, pos:9);
    _ssh_cmd_error += payload;
    val = update_window_size(size:strlen(payload));
    if (val != 0)
      break;
  }
  # nb: 98 == SSH_MSG_CHANNEL_REQUEST. There are several reasons,
  #     such as keepalive@openssh.com packets.
  else if (ord(payload[0]) == SSH2_MSG_CHANNEL_REQUEST)
  {
    want_reply = ord(payload[strlen(payload)-1]);
    payload = getstring(buffer:payload, pos:5);
    if (want_reply && "keepalive@openssh.com" >!< payload)
    {
      payload = raw_int32(i:remote_channel);
      # Tectia Server 6+ does not like when we send the CHANNEL FAILURE packet
      if(_ssh_server_version !~ "SSH-2.0-[0-9.]+ SSH Tectia Server")
        send_ssh_packet(payload:payload, code:raw_int8(i:100));
    }
  }
  payload = recv_ssh_packet(timeout:timeout);
 }

 while ((ord(payload[0]) != SSH2_MSG_CHANNEL_CLOSE) && (ord(payload[0]) != 0))
 {
  if (ord(payload[0]) == SSH2_MSG_CHANNEL_REQUEST)
  {
    payload = getstring(buffer:payload, pos:5);
    if ("keepalive@openssh.com" >< payload)
      keepalives++;

    if (("exit-status" >!< payload && "eow@openssh.com" >!< payload) || (SONICWALL_SSH && keepalives >= 2))
      break;
  }
  else if (ord(payload[0]) == SSH_MSG_DISCONNECT)
  {
    _ssh_cmd_error = strcat(
      _ssh_cmd_error,
      'The host responded with the following error message : \'', getstring(buffer:payload, pos:5), '\'.'
    );
    cret = ssh_close_channel(end:0);
    ssh_log_command_and_response(command: cmd);
    return NULL;
  }
  else if ((ord(payload[0]) == SSH2_MSG_CHANNEL_DATA) || (ord(payload[0]) == SSH2_MSG_CHANNEL_EXTENDED_DATA))
  {
    keepalives = 0;
    tempbuf = getstring(buffer:payload, pos:5);

    # Strip out escape sequences that might obscure the prompt; eg,
    #   0x00:  1B 5B 30 31 3B 33 32 6D 6E 65 73 73 75 73 40 65    .[01;32mnessus@e
    #   0x10:  78 61 6D 70 6C 65 2E 63 6F 6D 1B 5B 30 31 3B 33    xample.com.[01;3
    #   0x20:  34 6D 20 7E 20 24 1B 5B 30 30 6D 20                4m ~ $.[00m
    if (su || noexec || cisco) tempbuf = remove_escape_sequences(tempbuf);

    if (ord(payload[0]) == SSH2_MSG_CHANNEL_DATA)
    {
      recv_buffer += tempbuf;
      if ( sent_dbegin >< recv_buffer ) does_echo = 1;
    }
    val = update_window_size(size:strlen(tempbuf));
    if (val != 0)
    {
      break;
    }

    # End of su/sudo command
    if (!isnull(su) && (dend >< tempbuf || derror >< tempbuf))
    {
     if (su == SU_SU && spass < 2)
     {
       # Check for cases in which the escalation account doesn't exist and the target doesn't just prompt for a password.
       line = egrep(pattern:'(su: (user .+ does not exist|Unknown id: |unknown login: )|[0-9]+-[0-9]+ User "[^"]+" does not exist\\.)', string:recv_buffer);
       if (
         'su: user ' + root + ' does not exist' >< line ||
         ' User "' + root + '" does not exist.' >< line ||   # AIX 6.1
         'su: unknown login: ' + root >< line ||             # FreeBSD
         'su: Unknown id: ' + root >< line                   # Solaris 11
       )   # nb: this shouldn't fail.
       {
          line = ereg_replace(pattern:'^.*?([^ \\t]*su: (user|Unknown id:|unknown login:) .+|[0-9]+-[0-9]+ User "[^"]+" does not exist\\.)', replace:"\1", string:line);
          _ssh_cmd_error = chomp(line);
          ssh_close_channel(end:0);
          ssh_log_command_and_response(command: cmd);
          return NULL;
      }
       recv_buffer = NULL;
     }
     else
       break;
    }

    # privilege elevation: shell prompt -> sends command
    if (cisco)
    {
      if (strlen(tempbuf) > 0) last = tempbuf[strlen(tempbuf) - 1];
      else last = NULL;
      if (last == " " && strlen(tempbuf) > 1) last = tempbuf[strlen(tempbuf) - 2];

      cisco_ltempbuf = tolower(tempbuf);
      cisco_is_paging = (
          "--more--" >< cisco_ltempbuf ||
          "<--- more --->" >< cisco_ltempbuf ||
          # In some cases, the page prompt is split between data packets, in those rare cases we must detect it in
          # the cumulative recv_buffer
          (strlen(cisco_ltempbuf) < 9 && eregmatch(pattern:"(--[Mm]ore--|<--- [Mm]ore --->)\s*$", string:recv_buffer))
      );

      if (
        spass == 0 &&
        (
          last == "#" ||
          (last == ">" && strlen(enable_pass) == 0)
        )
      ) spass = 2;

      if (spass == 0 &&
          "Enter session number to resume or press <Enter>" >< tempbuf)
      {
          payload = raw_int32(i:remote_channel) + putstring(buffer:'\n');
          send_ssh_packet(payload:payload, code:raw_int8(i:94));
      }

      if (spass == 0 && cisco_is_paging)
      {
        payload = raw_int32(i:remote_channel) + putstring(buffer:' ');
        send_ssh_packet(payload:payload, code:raw_int8(i:94));
      }
      else if (spass == 0 && last == ">" && strlen(enable_pass) > 0)
      {
        payload = raw_int32(i:remote_channel) + putstring(buffer:'enable\n');
        send_ssh_packet(payload:payload, code:raw_int8(i:94));
        spass = 1;
      }
      else if (
        spass == 2 &&
        (
          last == "#" ||
          (last == ">" && strlen(enable_pass) == 0)
        ) && !cisco_is_paging # The banner can page if its really long
      )
      {
        foreach line (split(recv_buffer))
        {
          # empty
        }
        cmd_prompt = line;
        cmd_prompt = ereg_replace(pattern:"^\r", replace:"", string:cmd_prompt);
        replace_kb_item(name:"/tmp/ssh_cmd/cmd_prompt", value:cmd_prompt);

        payload = raw_int32(i:remote_channel) + putstring(buffer:cmd+'\n');
        send_ssh_packet(payload:payload, code:raw_int8(i:94));

        timeout += 15;
        spass = 4;

        recv_buffer = tempbuf = "";
      }
      else if (
        spass > 0 && spass <= 3 &&
        strlen(enable_pass)
      )
      {
        if (
          "% Access denied" >< tempbuf ||
          spass >= 3
        )
        {
          _ssh_cmd_error = 'The provided \'enable\' password does not appear to be correct.';
          ssh_log_command_and_response(command: cmd);
          return NULL;
        }

        if (is_password_prompt(tempbuf))
        {
          payload = raw_int32(i:remote_channel) + putstring(buffer:enable_pass+'\n');
          SSH_PACKET_LOG_SCRUB_STRING = enable_pass;
          send_ssh_packet(payload:payload, code:raw_int8(i:94));
          SSH_PACKET_LOG_SCRUB_STRING = FALSE;
          spass++;
        }
      }
      else if (spass == 4 || cisco_is_paging)
      {
        ltempbuf = tolower(tempbuf);
        if (cisco_is_paging)
        {
          payload = raw_int32(i:remote_channel) + putstring(buffer:' ');
          send_ssh_packet(payload:payload, code:raw_int8(i:94));
        }
        else if (last == '#' || last == '>') break;
      }
    }
    else
    {
      ltempbuf = chomp(tempbuf);

      if (strlen(ltempbuf) > 5) last5 = substr(ltempbuf, strlen(ltempbuf) - 5, strlen(ltempbuf) - 1);
      else last5 = ltempbuf;

      if (
        spass == 0 &&
        isnull(su) &&
        (
          "--More--" >< tempbuf ||
          "--MORE--" >< tempbuf ||
          "--More or " >< tempbuf ||
          "--more or " >< tempbuf ||
          egrep(pattern:"lines [0-9]+-[0-9]+(/[0-9]+ \(END\))? $", string:tempbuf)
        )
      )
      {
        spass = 4;
      }

      if("Press return to continue" ><tempbuf && spass == 4)
      {
        payload = raw_int32(i:remote_channel) + putstring(buffer:'\n');
        send_ssh_packet(payload:payload, code:raw_int8(i:94));
      }

      if (spass == 0 && (("Press any key to continue" >< tempbuf) || ("Press Enter to continue" >< tempbuf) || ("--More--" >< tempbuf)) )
      {
        payload = raw_int32(i:remote_channel) + putstring(buffer:'\n');
        send_ssh_packet(payload:payload, code:raw_int8(i:94));

        recv_buffer = tempbuf = "";
      }
      else if (spass == 0 && ('Press \'a\' to accept' >< tempbuf))
      {
        # Fortigate devices may configured to display a warning banner after login
        payload = raw_int32(i:remote_channel) + putstring(buffer:'a');
        send_ssh_packet(payload:payload, code:raw_int8(i:94));

        recv_buffer = tempbuf = "";
      }
      else if (
        spass == 0 &&
        (
          (last5_prompt && last5_prompt >< last5) ||
          (
            SONICWALL_SSH &&
            strlen(cmd_prompt) &&
            cmd_prompt >< tempbuf &&
            stridx(tempbuf, cmd_prompt) == strlen(tempbuf) - strlen(cmd_prompt)
          ) ||
          (
            !SONICWALL_SSH &&
            !last5_prompt &&
            (':' >< last5 || "$" >< last5 || "#" >< last5 || ">" >< last5 || "%" >< last5 || " ~]" >< last5) &&
            "##" >!< last5
          )
        )
      )
      {
        if (isnull(su) && noexec)
        {
          foreach line (split(recv_buffer))
          {
            # empty
          }
          cmd_prompt = line;

          replace_kb_item(name:"/tmp/ssh_cmd/cmd_prompt", value:cmd_prompt);
          payload = raw_int32(i:remote_channel) + putstring(buffer:cmd+'\n');
          send_ssh_packet(payload:payload, code:raw_int8(i:94));

          spass = 4;

          if("ACOS system is ready now" >< recv_buffer) ACOS_SSH = TRUE;
          recv_buffer = tempbuf = "";
        }
        else
        {
          # bump this down to 256 from 1024 for SunOS
          for ( sub1 = 0 ; sub1 < strlen(cmd) ; sub1 += 256 )
          {
            if ( strlen(cmd) <= sub1 + 255 )
              sub2 = strlen(cmd) - 1;
            else
              sub2 = sub1 + 255;
            cmdd = substr(cmd, sub1, sub2);
            payload = raw_int32(i:remote_channel) + putstring(buffer:cmdd);
            send_ssh_packet(payload:payload, code:raw_int8(i:94));
          }
          spass = 1;
        }
      }
      else if (isnull(su) && spass == 4 && (!ACOS_SSH || isnull(ACOS_SSH)))
      {
        ltempbuf = tolower(tempbuf);
        # nb: FireEye on occasion.
        if ("There is no -o option  (press RETURN)" >< recv_buffer)
        {
          payload = raw_int32(i:remote_channel) + putstring(buffer:'\n ');
          send_ssh_packet(payload:payload, code:raw_int8(i:94));
        }
        else if (
          "-- more --" >< ltempbuf ||
          "--more--" >< ltempbuf ||
          "---(more)---" >< ltempbuf ||
          "--more or (q)uit" >< ltempbuf ||
          "--More or (q)uit" >< ltempbuf ||
          egrep(pattern:"--+ ?\(?more ?([0-9]+%\))?--+", string:ltempbuf) ||

          # FireEye
          egrep(pattern:"lines [0-9]+-[0-9]+(/[0-9]+ \(end\))? $", string:ltempbuf) ||

          "next page: space" >< ltempbuf ||
          "Press enter to continue" >< ltempbuf ||
          "press any key to continue" >< ltempbuf ||
          (SONICWALL_SSH && egrep(pattern:"--MORE--$", string:recv_buffer))
        )
        {
          if (!pagination_prompt)
          {
            foreach line (split(recv_buffer))
            {
              # empty
            }
            pagination_prompt = line;
          }
          payload = raw_int32(i:remote_channel) + putstring(buffer:' ');
          send_ssh_packet(payload:payload, code:raw_int8(i:94));
        }
        else if ((( last5_prompt && last5_prompt >< last5) || (!last5_prompt && "##" >!< last5 && (':' >< last5 || "$" >< last5 || "#" >< last5 || ">" >< last5 || "%" >< last5 ))))
        {
          break;
        }
      }
      else if (isnull(su) && spass == 4 && ACOS_SSH && (">" >< last5 || "#" >< last5)) break;

      # su/sudo: set password if needed
      if (
        !isnull(su) &&
        (
          is_password_prompt(tempbuf) ||
          (
            su == SU_PBRUN &&
            'Authenticate ' + _ssh_current_user + ': ' >< tempbuf
          )
        )
      )
      {
        if ( su == SU_SU_AND_SUDO && spass == 1 && su_sudo_pass < 2 )
        {
         payload = raw_int32(i:remote_channel) + putstring(buffer:string(supass, '\n'));
         SSH_PACKET_LOG_SCRUB_STRING = supass;
         send_ssh_packet(payload:payload, code:raw_int8(i:94));
         SSH_PACKET_LOG_SCRUB_STRING = FALSE;
         su_sudo_pass ++;
         if ( su_sudo_pass == 2 ) spass = 2;
        }
        else if ( ! isnull(supass) && spass == 1 )
        {
         payload = raw_int32(i:remote_channel) + putstring(buffer:string(supass, '\n'));
         SSH_PACKET_LOG_SCRUB_STRING = supass;
         send_ssh_packet(payload:payload, code:raw_int8(i:94));
         SSH_PACKET_LOG_SCRUB_STRING = FALSE;
         spass = 2;
        }
        else if ( isnull(supass) || spass >= 2 ) # Password failed, or stray 'Password:' string in the command output
        {
           _ssh_cmd_error = strcat(
             _ssh_cmd_error,
             "Either the Escalation password was specified incorrectly in the scan", '\n',
             "policy or was not specified despite being required. Or there was a", '\n',
             "stray password prompt (eg, 'Password:') in the command output."
           );
           cret = ssh_close_channel(end:0);
           ssh_log_command_and_response(command: cmd);
           return NULL;
        }
      }
    }
  }
  payload = recv_ssh_packet(timeout:timeout);
 }


 end = 0;
 # solaris never sends back the close message with a tty
 # HP ProCurve, with Mocana or Comware SSH, doesn't either.
 if (
   ord(payload[0]) == SSH2_MSG_CHANNEL_CLOSE ||
   (!isnull(su) && bugged_sshd) ||
   (noexec && ereg(pattern:"(Mocana SSH|-Comware-)", string:_ssh_server_version))
 ) end = 1;

 # Close channel unless noclose set to TRUE.
 if (isnull(noclose) || noclose == FALSE)
 {
    cret = ssh_close_channel(end:end);
    if (cret != 0)
    {
     _ssh_cmd_error = strcat(
       _ssh_cmd_error,
       'Nessus failed to close SSH channel. ' + get_ssh_error()
     );
     ssh_log_command_and_response(command: cmd);
     return NULL;
    }
 }

 ret = recv_buffer;

 if (cisco)
 {
   # remove the command, which Cisco echoes back as the first line.
   if (strlen(ret) > 0 && strlen(cmd) > 0 && strlen(ret) >= strlen(cmd) && stridx(ret, cmd) == 0)
   {
     ret = substr(ret, strlen(cmd));
     ret = ereg_replace(pattern:"^[\r\n]+", replace:"", string:ret);
   }

   # remove the final prompt.
   if (cmd_prompt && cmd_prompt >< ret)
   {
     val = stridx(ret, cmd_prompt);
     if (val > 0 && val == strlen(ret) - strlen(cmd_prompt)) ret = substr(ret, 0, val-1);
     else if (ret == cmd_prompt) ret = "";
   }

   # remove pagination.
   ret = ereg_replace(pattern:'\r\n ?(--More--|<--- More --->) ?(\x08+ +)+\x08+', replace:'\r\n', string:ret);
   if (ret) ret = str_replace(find:'\x1b\x5b7m--More--\x1b\x5bm\x0d\x21\x1b\x5b\x4b\n', replace:'\r\n', string:ret);
 }

 if (isnull(su))
 {
   if (ret)
   {
     # nb: from a FireEye.
     if (stridx(ret, '% Unrecognized command "') >= 0)
     {
       _ssh_cmd_error = strcat(_ssh_cmd_error, chomp(ret));
       ssh_log_command_and_response(command: cmd);
       return NULL;
     }
     # nb: from an HP ProCurve switch when running a command
     #     directly rather than through a shell.
     else if (
      stridx(ret, "SSH command execution is not supported.") == 0 ||
      stridx(ret, "% Unrecognized command found at '^' position") >= 0
     )
     {
       _ssh_cmd_error = strcat(_ssh_cmd_error, chomp(ret));
       ssh_log_command_and_response(command: cmd);
       return NULL;
     }
     # nb: from a Juniper router running Junos.
     else if (stridx(ret, "error: syntax error, expecting <command>: -c") >= 0)
     {
       _ssh_cmd_error = strcat(_ssh_cmd_error, chomp(ret));
       ssh_log_command_and_response(command: cmd);
       return NULL;
     }
     # nb: from a NetApp.
     else if (stridx(ret, "not found.  Type '?' for a list of commands") >= 0)
     {
       _ssh_cmd_error = strcat(_ssh_cmd_error, chomp(ret));
       ssh_log_command_and_response(command: cmd);
       return NULL;
     }
     # nb: from NetApp (clustered)
      else if ( stridx(ret, "Error: Ambiguous command.") >= 0 || 
                ( 
                  stridx(ret, "Error:") >=0 && 
                  stridx(ret, "is not a recognized command") >=0
                )
              )
     {
       _ssh_cmd_error = strcat(_ssh_cmd_error, chomp(ret));
       return NULL;
     }
     # nb: from a Riverbed Steelhead.
     else if (stridx(ret, "Riverbed ssh: ssh remote command is not allowed") >= 0)
     {
       _ssh_cmd_error = strcat(_ssh_cmd_error, chomp(ret));
       ssh_log_command_and_response(command: cmd);
       return NULL;
     }
     # nb: from a Sonicwall firewall.
     else if ((stridx(ret, '%% Syntax error (no matching command):\r\n%% ') >= 0) ||
              (stridx(ret, "% Error encountered at '^' marker:") >= 0))
     {
       # exception for sonicwall v6, required by ssh_get_info.nasl
       if (cmd != 'show device')
       {
         _ssh_cmd_error = strcat(_ssh_cmd_error, chomp(ret));
         ssh_log_command_and_response(command: cmd);
         return NULL;
       }
     }
     else if (noexec || nosetup)
     {
       # nb: handle FireEye change of state.
       if (!nosetup && cmd == "enable" && cmd_prompt && preg(pattern:"> $", string:cmd_prompt))
       {
         cmd_prompt = ereg_replace(pattern:"> $", replace:"# ", string:cmd_prompt);
         replace_kb_item(name:"/tmp/ssh_cmd/cmd_prompt", value:cmd_prompt);
       }

       if (stridx(ret, ' '+cmd) == 0) ret = substr(ret, 1);

       if (stridx(ret, cmd+'\n') == 0) ret = ret - (cmd+'\n');
       else if (stridx(ret, cmd+' \n') == 0) ret = ret - (cmd+' \n');
       else if (stridx(ret, cmd+'\r\n') == 0) ret = ret - (cmd+'\r\n');
       else if (stridx(ret, cmd+' \r\n') == 0) ret = ret - (cmd+' \r\n');
       else if (stridx(ret, cmd+'\r\r\n') == 0) ret = ret - (cmd+'\r\r\n');

       if (
         cmd >< ret &&
         stridx(ret, cmd) == strlen(ret) - strlen(cmd)
       ) ret = ret - cmd;

       if (cmd_prompt)
       {
         ret = ereg_replace(pattern:"[\x07]+$", replace:"", string:ret);

         val = -1;
         if (cmd_prompt >< ret) val = stridx(ret, cmd_prompt);
         else if (cmd_prompt=~ " $")
         {
           cmd_prompt = ereg_replace(pattern:" $", replace:"", string:cmd_prompt);
           if (cmd_prompt >< ret) val = stridx(ret, cmd_prompt);
         }

         if (val > 0 && val == strlen(ret) - strlen(cmd_prompt)) ret = substr(ret, 0, val-1);
         else if (val == 0) ret = ret - cmd_prompt;
       }

       if (pagination_prompt && pagination_prompt >< ret)
       {
         tempbuf = "";
         foreach line (split(ret))
         {
           line = ereg_replace(pattern:"^--+ *\(?[Mm]ore ?([0-9]+%)?\)? *--+(( \x08+)+|(\x0d +\x0d*)?)", replace:"", string:line);
           line = ereg_replace(pattern:"(lines [0-9]+-[0-9]+(/[0-9]+ \(END\))? \x0d(\x07\x0d)?)", replace:"", string:line);
           if (is_huawei_device())
           {
             line = ereg_replace(pattern:"  ---- More ----                                          ", replace:"", string:line);
           }

           if (stridx(line, pagination_prompt) != 0) tempbuf += line;
         }
         ret = tempbuf;
       }
       ret = chomp(ret);
     }
   }
 }

 if (!isnull(su))
 {
  if (derror >< ret)
  {
    # Try to capture the error message.
    foreach line (split(ret, keep:TRUE))
    {
      if (
        code_begin >< line || code_end >< line ||
        ereg(pattern:": +(command not found|not found|No such file or directory)", string:line) ||
        (
          (su == SU_SUDO || su == SU_SU_AND_SUDO) &&
          "is not in the sudoers file" >< line
        ) ||
        (
          (su == SU_SU || su == SU_SU_AND_SUDO) &&
          ereg(pattern:"su: +(Authentication failure|incorrect password|Sorry)", string:line)
        ) ||
        (
          (su == SU_SUDO || su == SU_SU_AND_SUDO || su == SU_DZDO) &&
          (
            "Sorry, user" >< line ||
            "sorry, you are not allowed to set" >< line
          )
        )
      )
      {
        if (su == SU_DZDO)
        {
          if ("Sorry, user" >< line) line = strstr(line, "Sorry, user");
          if ("sorry, you are not allowed to set" >< line) line = strstr(line, "sorry, you are not allowed to set");
        }

        if (ereg(pattern:": +(command not found|not found|No such file or directory)", string:line))
        {
          line = ereg_replace(pattern:"^.* +([^ ]+: +(command not found|not found|No such file or directory))", replace:"\1", string:line);
        }

        _ssh_cmd_error = strcat(_ssh_cmd_error, line);
      }
    }
    if (_ssh_cmd_error) _ssh_cmd_error = chomp(_ssh_cmd_error);

    ssh_log_command_and_response(command: cmd);
  }
  if (dbegin >!< ret || dend >!< ret)
  {
    ssh_log_command_and_response(command: cmd);
    return NULL;
  }
  if (dbegin >< ret)
    ret = substr(strstr(ret, dbegin), strlen(dbegin), strlen(ret)-1);
  if (dend >< ret)
  {
   while ( ret[0] == '\n' ) ret = substr(ret, 1, strlen(ret) - 1);
   ret = substr(ret, 0, stridx(ret, dend)-1);
  }
 }

 ssh_log_command_and_response(command: cmd, response: ret);
 return ret;
}

#-----------------------------------------------------------------#
# Return errors happened during ssh_cmd()                        #
#-----------------------------------------------------------------#
function ssh_cmd_error()
{
 return _ssh_cmd_error;
}

#------------------------------------------------------------------#
# Connection re-use                                                #
#------------------------------------------------------------------#


#
# Release the shared SSH connection so that another script can write to
# it
#
function ssh_close_connection()
{
 if ( _ssh_socket > 0 ) close(_ssh_socket);
 _ssh_socket = NULL;
}


function ssh_open_connection(exit_on_disconnect)
{
  local_var cert, host, login, passphrase, password, priv, pub, realm;
  local_var rc;
  local_var i;
  local_var alt_login, done, j;

  _ssh_ltype = 1;

  cert = kb_ssh_certificate();
  host = kb_ssh_host();
  login = kb_ssh_login();
  passphrase = kb_ssh_passphrase();
  password = kb_ssh_password();
  priv = kb_ssh_privatekey();
  pub = kb_ssh_publickey();
  realm = kb_ssh_realm();


  if (get_kb_item("SSH/login/failed"))
  {
    set_ssh_error(msg:"SSH was unable to login with any supplied credentials.");
    return 0;
  }

  if (!login)
  {
    set_ssh_error(msg:"Nessus needs a login account to open an SSH connection.");
    return 0;
  }

  if (!password && !priv && !pub && !cert)
  {
    set_ssh_error(msg:"Nessus needs either a password, a public and private keypair, or a"+'\n'+"certificate and private key to open an SSH connection.");
    return 0;
  }

  if (!password && (priv && !pub && !cert && (!defined_func("nasl_level") || nasl_level() < 6000)))
  {
    set_ssh_error(msg:"Nessus needs either a public and private key or a certificate and a"+'\n'+"private key to open an SSH connection using publickey authentication.");
    return 0;
  }

  _ssh_socket = open_sock_tcp(kb_ssh_transport());
  if (!_ssh_socket && kb_ssh_transport() != 22 && defined_func("rm_kb_item"))
  {
    rm_kb_item(name:"Secret/SSH/PreferredPort");
    _ssh_socket = open_sock_tcp(kb_ssh_transport());
  }

  if (!_ssh_socket)
    return 0;

  _ssh_current_port = kb_ssh_transport();
  replace_kb_item(name:"Ports/tcp/"+kb_ssh_transport(), value:TRUE);

  if (exit_on_disconnect) _exit_on_disconnect = TRUE;
  else _exit_on_disconnect = FALSE;

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
    close(_ssh_socket);

    set_kb_item(name:"SSH/login/failed", value:TRUE);

    # We may be done if there was a failure because the password
    # needs to be changed.
    if (password && "must be changed" >< get_ssh_error())
    {
      # Assume we are.
      done = TRUE;

      # If we have credentials for a different account, though, we're not done.
      if ( get_kb_item("Secret/SSH/0/login") )
      {
        for ( j = 0 ; TRUE ; j ++ )
        {
          alt_login = get_kb_item(strcat("Secret/SSH/", j, "/login"));
          if (isnull(alt_login)) break;
          if (alt_login != login)
          {
            done = FALSE;

            # there is a different set of privilege escalation & Kerberos (6.x or later) data associated with each SSH account in the policy.
            # reaching this code indicates authentication failed, which means there's no point in using the currently loaded data
            kb_rm_ssh_data();

            break;
          }
        }
      }

      if (done) return 0;
    }

    if ( get_kb_item("Secret/SSH/0/login") )
    {
      for ( i = 0 ; TRUE ; i ++ )
      {
        _ssh_socket = open_sock_tcp(kb_ssh_transport());
        if(!_ssh_socket)
          return 0;
        login = get_kb_item(strcat("Secret/SSH/", i, "/login"));
        if(isnull(login))
          return 0;
        password = get_kb_item(strcat("Secret/SSH/", i, "/password"));
        cert = get_kb_item(strcat("Secret/SSH/", i, "/certificate"));
        priv = kb_ssh_alt_privatekey(i);
        passphrase = get_kb_item(strcat("Secret/SSH/", i, "/passphrase"));
        realm = kb_load_alt_kerberos_data(i);
        kb_load_alt_escalation_data(i);

        rc = ssh_login(login:login, password:password, priv:priv, passphrase:passphrase, host:host, cert:cert, realm:realm);

        # We always wipe out SSH login data, if rc == 0 we will reload it properly
        # We _have_ to do this to keep the KB state for this information clean
        # otherwise we risk mixing kerb / escalation information between credential
        # sets.
        kb_rm_ssh_data();

        if ( rc == 0 )
        {
          #
          # Use these credentials from now on
          #
          rm_kb_item(name:"SSH/login/failed");
          replace_kb_item(name:"Secret/SSH/login", value:login);
          rm_kb_item(name:"Secret/SSH/publickey");

          # By unsetting SSH/0/login we will never test any ssh accounts
          # in subsequent calls to ssh_open_connection, we will always
          # use the set we load into the kb below.
          rm_kb_item(name:"Secret/SSH/0/login");

          # Re-load alternate data, the log in worked
          kb_load_alt_escalation_data(i);
          kb_load_alt_kerberos_data(i);

          if (!isnull(password))
            replace_kb_item(name:"Secret/SSH/password", value:password);
          else
            rm_kb_item(name:"Secret/SSH/password");

          if (!isnull(cert))
            replace_kb_item(name:"Secret/SSH/certificate", value:cert);
          else
            rm_kb_item(name:"Secret/SSH/certificate");

          if (!isnull(priv))
            replace_kb_item(name:"Secret/SSH/privatekey", value:hexstr(priv));
          else 
            rm_kb_item(name:"Secret/SSH/privatekey");

          if (!isnull(passphrase))
            replace_kb_item(name:"Secret/SSH/passphrase", value:passphrase);
          else
            rm_kb_item(name:"Secret/SSH/passphrase");

          break;
        }

        close(_ssh_socket);

        # We're done if there was a failure because the password
        # needs to be changed.
        if (password && "must be changed" >< get_ssh_error())
        {
          # Assume we are.
          done = TRUE;

          # If we have credentials left for a different account, though, we're not done.
          if ( get_kb_item("Secret/SSH/0/login") )
          {
            for ( j = i+1 ; TRUE ; j ++ )
            {
              alt_login = get_kb_item(strcat("Secret/SSH/", j, "/login"));
              if (isnull(alt_login)) break;
              if (alt_login != login)
              {
                done = FALSE;
                break;
              }
            }
          }

          if (done) return 0;
        }
      }
    }
    else return 0;
  }

  _ssh_ltype = 1;

  return 1;
}


##
# Verifies that the prompt presented by the
# "keyboard-interactive" login method of SSH notes a valid
#
# @remark This is a simple check only ie we use the >< on
#         both the buffer passed in and its lower case
#         counter part, we do not use regex
#
# @remark If you don't pass in the user argument, don't expect
#         to match user specific prompts like "Pasword for <user>"
#
# @anonparam required string : buffer to check
# @anonoparm optional string : name of user being logged in
#
# @return TRUE  if buffer contains a known valid password prompt
#         FALSE otherwise
##
function buffer_contains_password_prompt()
{
  local_var buf, user, prompt, prompts;
  buf  = _FCT_ANON_ARGS[0];
  user = _FCT_ANON_ARGS[1];
  if(isnull(buf))
    return FALSE;
  if(isnull(user))
    user = '';
  prompts = make_list(
      # Strange prompts
      'Enter PASSCODE:',
      "Password for "+user+"@",
      'Enter password for '+user+':',
      # Language variants of "password:" we should add more here in the future
      # this is the most common
      'password:',
      'contrase'+'\xc3\xb1'+'a:', # Spanish UTF-8 for password
      'contrase'+'\x11'+'a:' # Spanish ISO-8859-1 for password

  );
  foreach prompt (prompts)
  {
    if(prompt >< tolower(buf) || prompt >< buf)
      return TRUE;
  }
  return FALSE;
}

function is_huawei_device()
{
  return "DOPRA" >< _ssh_server_version;
}

function remove_escape_sequences()
{
  local_var s;

  s = _FCT_ANON_ARGS[0];

  s = ereg_replace(pattern:'\x1b\\[[0-9]+(;[0-9]+)?[A-Za-z]', replace:'', string:s);
  s = ereg_replace(pattern:'\x1b\\[\\?[0-9]+[A-Za-z]', replace:'', string:s);
  s = ereg_replace(pattern:'\x1b\\[[mK]', replace:'', string:s);
  s = ereg_replace(pattern:'\x1b=\x0d', replace:'', string:s);
  s = ereg_replace(pattern:'\x1b\x3e', replace:'', string:s);
  s = ereg_replace(pattern:'\x1b[0-9]*E', replace:'\n', string:s);

  return s;
}
