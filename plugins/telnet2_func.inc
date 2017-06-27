#TRUSTED 0ff3bf0bfdc488f9a15aa3969e17651b318b9a449cb198a38a7bbb44d4f88b0c6c4292c19fa92d8d3f99d9553870f53f5f593473637efd021a5007be552ead6c3411c80ca401aeff54ea1717548af1f79b62e266c65b6f1bca727f85bb25e7e83c200524c4d88be484def894f27b159110aa4c7f302a25fe9e8314ba76842987b6f26621e0a9b1295ae268eeced17b9a31a634fe03543e52cabcf542438b8a528672c05a03676e015374e132bee54cb24dd74dd2ea2cd03a62bc52622d39f9723ce9061dd3a4fd2a79551baec8f0dc6fb765bcaa1854fec822d725946df25cdf95fc0b7010cd6833316cc15310cc678b3986657609d37437d72ddc051319842dbc0dba465a7c7207b42e298da7312c7202a1a12f49238a66e1390472010b9a100b77843ed9b65f00c2831ddc3448226e3ab3c7395470258d30368d87a64b0487ff214c247c7fa4403378ccd432eb87f900510cee493d7a436ee8f595e369b7ae85618f97dc49a0c09f63a20c1f27c759c535136f6f6bc5bb52dba13d100a448d57a972ca7b97a8802335e4fd7ee043fbf5ae3ca040025898d6aa2ef24504a0e9e9e2e289121c9158bfff9bc2b440384f1ff8b78e21494c3e87ddca985a722421600df577f29711e0482c557f969b4123814ba7c0fc27e39ea0e4b655b7631b302c279c5d00e01ea263ae358614a0574b1988c0ce35a2cd7d228391e2faf26d4d
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# telnet2_func.inc 
# Revision: 1.6
#


# NB: you need to include byte_func.inc.

OPT_TERM_TYPE      = 24;   # Termninal Type
OPT_NEG_ABOUT_SIZE = 31;   # Negotiate About Size
OPT_ENV            = 36;   # Environment option
OPT_ENC            = 38;   # Encryption Option (http://tools.ietf.org/html/rfc2946)
OPT_NEW_ENV        = 39;   # New Environment option
OPT_TN3270E        = 40;   # TN3270E option (http://www.faqs.org/rfcs/rfc1647.html)
OPT_STARTTLS       = 46;   # Start-TLS option (http://tools.ietf.org/id/draft-altman-telnet-starttls-02.txt)

CMD_SE    = 240;  # End of subnegotiation parameters.
CMD_NOP   = 241;  # No operation.
CMD_DM    = 242;  # Data stream portion of a synch (TCP Urgent notification).
CMD_BREAK = 243;  # NVT character BRK.
CMD_IP    = 244;  # Interrupt Process
CMD_AO    = 245;  # Abort Output
CMD_AYT   = 246;  # Are You There
CMD_EC    = 247;  # Erase Character
CMD_EL    = 248;  # Erase Line
CMD_GA    = 249;  # Go Ahead
CMD_SB    = 250;  # Subnegotiation
CMD_WILL  = 251;
CMD_WONT  = 252;
CMD_DO    = 253;
CMD_DONT  = 254;
CMD_IAC   = 255;

#Encryption Commands (rfc2946)
CMD_IS               = 0;
CMD_SUPPORT          = 1;
CMD_REPLY            = 2;
CMD_START            = 3;
CMD_END              = 4;
CMD_REQUEST_START    = 5;
CMD_REQUEST_END      = 6;
CMD_ENC_KEYID        = 7;
CMD_DEC_KEYID        = 8;

#Encryption Types (rfc2946)
#NULL             0;
ENC_DES_CFB64    = 1;
ENC_DES_OFB64    = 2;
DES3_CFB64       = 3;
DES3_OFB64       = 4;
CAST5_40_CFB64   = 8;
CAST5_40_OFB64   = 9;
CAST128_CFB64    = 10;
CAST128_OFB64    = 11;

#Suboption Commands (http://www.ietf.org/rfc/rfc2953.txt)
OFB64_IV         = 1;
OFB64_IV_OK      = 2;
OFB64_IV_BAD     = 3;

NO_STATE  = 0;

global_var _tsock, _tport, _timeout, _time_start, _toptions;
global_var _terrno;
global_var _starttls_supported, _starttls_sent;

##
# Initiates the telnet2 library
#
# @param port Telnet port (default 23)
# @param options Telnet options to set
# @param timeout Timeout to wait for
#
# @return TRUE/FALSE if the library was initialized
##
function telnet2_init (port, options, timeout)
{
  if (!isnull(port))
    _tport = port;
  else
  {
    _tport = get_kb_item("Services/telnet");
    
    if (!_tport)
      _tport = 23;
  }

  if (!get_port_state(_tport))
    return FALSE;

  _toptions = options;
  _timeout = timeout;
  _time_start = unixtime();
  _starttls_sent = FALSE;

  _terrno = 0;
  _tsock = open_sock_tcp(_tport);
  if (!_tsock)
    return FALSE;

  return TRUE;
}

##
# Reads a single byte from the socket
#
# @anonparam len If specified will read up to the length
#
# @return Results from the socket read based on the len (default 1)
##
function telnet_read ()
{
  local_var len;

  if (max_index(_FCT_ANON_ARGS) > 0)
  {
    len = _FCT_ANON_ARGS[0];
    return recv(socket:_tsock, length:len);
  }

  return recv(socket:_tsock, length:1, min:1, timeout:0);
}

##
# Writes data to the telnet connection
#
# @anonparam data The data to write to the telnet connection
##
function telnet_write ()
{
  local_var data;
  data = _FCT_ANON_ARGS[0];

  send(socket:_tsock, data:data);
}

##
# Sends a telnet command, prepends CMD_IAC to the command
#
# @param cmd Telnet command
# @param data Extra data/arguments to the telnet command
##
function telnet_send_cmd (cmd, data)
{
  telnet_write (mkbyte(CMD_IAC) + mkbyte(cmd) + data);
}

##
# Sends the telnet wont command
#
# @anonparam data Parameters to the wont command
##
function telnet_wont ()
{
  local_var data;
  data = _FCT_ANON_ARGS[0];

  return telnet_send_cmd (cmd:CMD_WONT, data:data);
}

##
# Sends the telnet dont command
#
# @anonparam data Parameters to the dont command
##
function telnet_dont ()
{
  local_var data;
  data = _FCT_ANON_ARGS[0];

  return telnet_send_cmd (cmd:CMD_DONT, data:data);
}

##
# Sends the telnet will command
#
# @anonparam data Parameters to the will command
##
function telnet_will ()
{
  local_var data;
  data = _FCT_ANON_ARGS[0];

  return telnet_send_cmd (cmd:CMD_WILL, data:data);
}

##
# Sends a telnet suboption
#
# @param cmd Suboption command to send
# @param data Parameters to the command
##
function telnet_send_suboption (cmd, data)
{
  telnet_send_cmd (cmd:CMD_SB, data:mkbyte(cmd)+data);
  telnet_send_cmd (cmd:CMD_SE, data:NULL);
}

##
# Negoiaties the telnet terminal type
#
# @anonparam data Telnet terminal type, breaks if not 0x01
##
function telnet_do_term_type()
{
  local_var data;
  data = _FCT_ANON_ARGS[0];

  # if not "Sends your terminal type" (0x01)
  if (strlen(data) <= 0 || ord(data[0]) != 0x01)
    return;

  data = mkbyte(0) + # Here is my term type
    "XTERM";

  telnet_send_suboption (cmd:OPT_TERM_TYPE, data:data);
}

##
# Negiotates the telnet about size with a fixed width 126 and height 49
#
# @anonparam data Not used
##
function telnet_do_neg_about_size()
{
  local_var data;
  data = _FCT_ANON_ARGS[0];

  data = mkword(126) + # Width
    mkword(49);   # Height

  telnet_send_suboption (cmd:OPT_NEG_ABOUT_SIZE, data:data);
}

##
# Starts the TTL process for telnet
#
# @anonparam data Extra TTLS options
##
function telnet_do_starttls()
{
  local_var data;
  data = _FCT_ANON_ARGS[0];

  if (strlen(data) <= 0 || ord(data[0]) != 0x01)
    return;

  _starttls_sent = TRUE;
}

##
# Checks to see if an option is registered
#
# @anonparam opt Option to search for
#
# @return True/False if the option is registered
##
function is_registered_option()
{
  local_var opt, options, found;
  opt = _FCT_ANON_ARGS[0];

  found = FALSE;
  foreach options (_toptions)
  {
    if (opt == options[0])
    {
      found = TRUE;
      break;
    }
  }

  return found;
}

##
# Finds and returns an option by name
#
# @anonparam opt Option to search for
#
# @return The value of the option searched for
##
function get_registered_option ()
{
  local_var opt, options, found;
  opt = _FCT_ANON_ARGS[0];

  found = NULL;

  foreach options (_toptions)
  {
    if (opt == options[0])
    {
      found = options;
      break;
    }
  }

  return found;
}

##
# Parses and handles telnet suboptions
#
# @anonparam data Block of the telnet subnegation packet to handle
##
function telnet_handle_suboption ()
{  
  local_var opt, xtra, len, option;
  local_var data;
  data = _FCT_ANON_ARGS[0];

  len = strlen(data);

  if (len < 1)
    return;

  if (len > 1)
    xtra = substr(data, 1, len-1);
  else
    xtra = NULL;
 
  opt = ord(data[0]);

  option = get_registered_option(opt);

  if (option != NULL)
    telnet_send_suboption (cmd:opt, data:option[1]); 
  else if (opt == OPT_TERM_TYPE)
    telnet_do_term_type(xtra);
  else if (opt == OPT_NEG_ABOUT_SIZE)
    telnet_do_neg_about_size(xtra);
  else if (opt == OPT_STARTTLS && _starttls_supported && !_starttls_sent)
    telnet_do_starttls(xtra);
 
 return;
}

##
# Telnet message loop, handles the protocol and passes control to the 
# `telnet_callback` function when a null byte is encountered or after 
# a command is parsed.
#
# @remark Any plugin calling this function requires a telnet_callback
# function.
##
function telnet_loop ()
{
  local_var byte, cmd, state, _subneg;

  state = NO_STATE;

  while (1)
  {
    # checks timeout first
    if ((unixtime()-_time_start) >= _timeout)
    {
      _terrno = ETIMEDOUT;
      return;
    }

    byte = telnet_read();

    if (isnull(byte))
    {
      if ( telnet_callback() == -1 ) return;
      continue;
    }

    cmd = ord(byte[0]);

    # before parsing data we make sure it is not IAC
    if (cmd == CMD_IAC)
    {
      state = CMD_IAC;
      continue;
    }

    if (state == CMD_IAC)
    {
      if (cmd < CMD_SE || cmd > CMD_DONT)
      {
        state = NO_STATE;
        continue;
      }

      state = cmd;

      if (cmd >= CMD_WILL && cmd <= CMD_DONT)
        continue;

      if (cmd == CMD_SB)
      {
        _subneg = NULL;
        continue;
      }

      if (cmd == CMD_SE)
      {
        telnet_handle_suboption(_subneg);
        if (_starttls_sent) return;
        _subneg = NULL;
        continue;
      }

      # must take care of other commands here
      continue;
    }

    if (state == CMD_DO)
    {
      if (is_registered_option(cmd) || cmd == OPT_TERM_TYPE || cmd == OPT_NEG_ABOUT_SIZE)
      {
        telnet_will(byte);
      }
      else if (cmd == OPT_STARTTLS && _starttls_supported && !_starttls_sent)
      {
        telnet_will(byte);
        telnet_send_suboption(cmd:OPT_STARTTLS, data:mkbyte(1));
      }
      else
        telnet_wont(byte);

      state = NO_STATE;
      continue;
    }

    if (state == CMD_DONT)
    {
      telnet_wont(byte);

      state = NO_STATE;
      continue;
    }

    if (state == CMD_WILL)
    {
      telnet_dont(byte);

      state = NO_STATE;
      continue;
    }

    if (state == CMD_SB)
    {
      _subneg += byte;
      continue;
    }

    if (state >= CMD_SE && state <= CMD_DONT)
    {
      state = NO_STATE;
      continue;
    }

    # we give the data to the callback function
    if ( telnet_callback(byte) == -1 ) return;
  }
}

##
# Tries to negotiate a telnet connection on an open socket using the START_TLS option.
#
# @param socket an open socket. (required) 
# @param encaps if specified, complete the SSL handshake using the type of encapsulation specified by 'encaps'. (optional)
#
# @return The socket if the connection could be upgraded or NULL otherwise
##
function telnet_starttls(socket, encaps)
{
  if (isnull(socket)) return NULL;

  _toptions = make_array();
  _tsock = socket;
  _terrno = 0;
  _timeout = get_read_timeout();
  _time_start = unixtime();

  _starttls_supported = TRUE;
  _starttls_sent = FALSE;

  telnet_loop();
  if (_terrno) return NULL;

  if (encaps)
  {
    if (!defined_func("socket_negotiate_ssl")) return NULL;
    return socket_negotiate_ssl(socket:socket, transport:encaps);
  }
  
  return socket;
}
