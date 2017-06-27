#TRUSTED a97251f627ba0e83c71197ba5347d0d2ca68394f8b3e739149d37aaf02dee8dd3c22bc461e68a46f570fa831542132749da4efa297bf412cb8f2a5280fe8d6ae0aec09e8be71ab231e5aa99b9f85e03f078fc5a4da6baa2037a57886ee626253e971f3402041d36223dff940543b33674677e1a2d7b17d9ac2f1d8f571b217ab07506cbb527b3cae94ac2d05cfbe70ed1dbb02e7004fd2f59e8ded36647c153d77f767abb4ab72b204c23ae2b388d9fb60556ccb2c49c21966e10e55cd3e5b6ac655de448e6b2b40a8c2ff6e93243a95ca1bc92747d8617d0d7be4a3e4e316de73700ea823ef77621371f3ea8799ac26eb87be6092ef2922d1d96ba48d6ee499c2fbba5ec340ac05feff459eea5094bb38a7fb6fd91cfd1c68ebc0c234eeed8a88c1119231f8dc6ae704cbdaf37583dd75c09f16406ba073ea7cb2814ba377f9d6d035cb5c47b1be9473c9e8364ec04bc83acd573b8456ba382f9de0699362a3f778da65d3710fe2dcf018dec6ed404a55f736d78a01b37c9a04fc9a93831e496a55c00ed49a838c1dbe7ec02b1b861f3876741fe30f4ec7c2eaec9a25a4c88ef8e6bb6a3e8bbbb2e52a60a23a32742e2a56314c1575ffff4eb82d021e87b808b8ef3d0f47a72bd2679f99bf67bda4b46bb0ea3f190db426ea1bcf9ca1aec4e4ac43b87af3c5f0c8fd712becb5da50d9f78976a5934f937a785030921d05c82b

#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision 1.0
#

#
# This header implements various features of the ComelitViP
# Remote App:
# https://play.google.com/store/apps/details?id=com.comelit.remotevip&hl=en
#

## successful_response return values
global_var RESET_CONNECTION = 0;
global_var MISSING_DATA = 1;
global_var BAD_TYPE = 2;
global_var DEVICE_CONNECTED = 3;

## recv_expected return values
global_var RCV_NULL = 0;
global_var WRONG_TYPE = 1;
global_var CORRECT_TYPE = 2;

##
# Adds the VIP header which looks like this:
#
# [00 06][2 bytes length][2 bytes channel id][00 00]
#
# The payload is then appended and sent.
#
# @param soc - the socket to send data over
# @param channel_id - the id of the channel we are sending on
# @param payload - the payload we want to send
#
# @return void
##
function vip_send(soc, channel_id, payload)
{
  # start with the preamble
  local_var output = '\x00\x06';

  # add the length in big endian order
  set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
  output += mkword(len(payload));

  # add the channel
  if (isnull(channel_id))
  {
    output += '\x00\x00';
  }
  else
  {
    output += channel_id;
  }

  # add the outro and payload
  output += '\x00\x00';
  output += payload;

  send(socket:soc, data:output);
  return;
}

##
# Reads the 8 byte frame header and then reads in the
# remaining frame. If channel_id is set then this
# function will keep consuming frames until it finds
# one on the provided channel.
#
# @param soc - the socket to recv 
# @param channel_id - the channel to receive data from
#
# @return the the message payload or NULL on failure
##
function vip_rcv(soc, channel_id)
{
  # get the preamble to find the length of the entire frame
  local_var preamble = NULL;
  local_var payload = NULL;
  do
  {
    preamble = recv(socket:soc, length:8, min:8);
    if (isnull(preamble))
    {
      return NULL;
    }

    # preamble always starts with 06 00
    if (getword(blob:preamble, pos:0) != 0x0600)
    {
      return NULL;
    }

    local_var length = getword(blob:preamble, pos:2);
    payload = recv(socket:soc, length:length, min:length, timeout:5);
    if (isnull(payload))
    {
      return NULL;
    }
  }
  while (!isnull(channel_id) &&
    getword(blob:preamble, pos:4) != getword(blob:channel_id));

  return payload;
}

##
# Create a new channel with the remote comelite device.
#
# @param soc - the socket to send data over
# @param type - the type of channel to open. ie. 'INFO' or 'CTPP'
# @param channel_id - the id of the channel we are sending on
# @param additional - extra data required to create the channel
#
# @return TRUE on success and false otherwise
##
function create_channel(soc, type, channel_id, additional)
{
  local_var payload = '\xcd\xab\x01\x00\x07\x00\x00\x00';
  payload += type;
  payload += channel_id;
  payload +='\x00';

  if (!isnull(additional))
  {
    payload += '\x00';
    payload += additional;
  }
  vip_send(soc:soc, channel_id:NULL, payload:payload);

  payload = vip_rcv(soc:soc);
  if (isnull(payload) || getword(blob:payload, pos:0) != 0xabcd)
  {
    return FALSE;
  }
  return TRUE;
}

##
# Close a channel with the remote comelite device. This function
# will consume responses from the server until it receives the
# 'Ok we closed the channel' message.
#
# @param soc - the socket to send data over
# @param channel_id - the id of the channel we are sending on
#
# @return void
##
function close_channel(soc, channel_id)
{
  local_var payload = '\xef\x01\x03\x00\x02\x00\x00\x00';
    payload += channel_id;
  vip_send(soc:soc, channel_id:'\x00\x00', payload:payload);

  # keep receiving frames until we can an ack or failure
  do
  {
    payload = vip_rcv(soc:soc);
  }
  while (!isnull(payload) && getword(blob:payload, 0) != 0x01ef);
}

##
# Receives a frame on the provided channel and verifies that
# the received frame has the correct 'type' field.
#
# @param soc - the socket to send data over
# @param channel_id - the id of the channel we are sending on
# @param expected_ack - the expected ack sequence
# @param type - the expected type (ie. 0x1800)
#
# @return returns RCV_NULL, WRONG_TYPE, or CORRECT_TYPE
##
function recv_expected(soc, channel_id, expected_ack, type)
{
  local_var payload = RCV_NULL;
  do
  {
    payload = vip_rcv(soc:soc, channel_id:channel_id);
    if (isnull(payload))
    {
      return RCV_NULL;
    }
  }
  while(!isnull(expected_ack) && getbyte(blob:payload, pos:5) != getbyte(expected_ack));

  if (getword(blob:payload, pos:0) != type)
  {
    return WRONG_TYPE;
  }
  return CORRECT_TYPE;
}

##
# A successful connection will receive three responses:
# 1800, 1840, and 1820. This function will attempt to
# receive these three items.
#
# @param soc - the socket to send data over
# @param channel_id - the id of the channel we are sending on
# @param expected_ack - the expected value of the ACK field
#
# @return one of four states:
#   1. RESET_CONNECTION: the caller should reset the CTPP connection
#   2. MISSING_DATA: missing one or more message
#   3. BAD_TYPE: An invalid type was encountered
#   4. DEVICE_CONNECTED: great success!
function successful_response(soc, channel_id, expected_ack)
{
  # A successful connection will receive three responses:
    # 1800, 1840, and 1820

  if (recv_expected(soc:soc, channel_id:channel_id,
    expected_ack:expected_ack, type:0x1800) != CORRECT_TYPE)
  {
    return RESET_CONNECTION;
  }

  local_var result = recv_expected(soc:soc, channel_id:channel_id,
    expected_ack:expected_ack, type:0x1840);
  if (result != CORRECT_TYPE)
  {
    return result;
  }

  result = recv_expected(soc:soc, channel_id:channel_id,
    expected_ack:expected_ack, type:0x1820);
  if (result == RCV_NULL)
  {
    return MISSING_DATA;
  }
  else if (result == WRONG_TYPE)
  {
    return BAD_TYPE;
  }

  return DEVICE_CONNECTED;
}

##
# This function will connect to the master. Before communicating with other
# devices, a master connection must be established.
#
# @param soc - the socket to send data over
# @param channel_id - the id of the channel we are sending on
# @param vip_address - the vip address of the master
# @param slave - the slave number used. Experience indicates all 1-15 are valid?
# @param direction - randomly generated direction values (2 bytes)
# @param seq - the initial sequence number (1 byte)
# @param ack - the initial ack number (1 byte)
# @param full_connect - TRUE if we want to establish a complete connection.
#
# @return TRUE on success and FALSE otherwise
##
function connect_to_master(soc, channel_id, vip_address, slave, direction,
  seq, ack, full_connect)
{
  local_var connect_request = '\xc0\x18';
  connect_request += direction;
  connect_request += seq;
  connect_request += ack;
  connect_request += '\x00\x11';
  connect_request += '\x00\x40';
  connect_request += mkword(rand() % 65535);
  connect_request += vip_address;
  connect_request += slave;
  connect_request += '\x00';
  connect_request += '\x10\x0e\x00\x00\x00\x00';
  connect_request += '\xff\xff\xff\xff';
  connect_request += vip_address;
  connect_request += slave;
  connect_request += '\x00';
  connect_request += vip_address;
  connect_request += '\x00\x00';
  vip_send(soc:soc, channel_id:channel_id, payload:connect_request);

  # increment the sequence number
  seq = mkbyte(getbyte(blob:seq) + 1);

  local_var connect_response = successful_response(soc:soc, channel_id:channel_id, expected_ack:seq);
  if (isnull(full_connect) || full_connect == FALSE || connect_response < DEVICE_CONNECTED)
  {
    return connect_response == DEVICE_CONNECTED;
  }

  # increment the ack number
  ack = mkbyte(getbyte(blob:ack) + 1);

  connect_request = '\x00\x18';
  connect_request += direction;
  connect_request += seq;
  connect_request += ack;
  connect_request += '\x00\x00';
  connect_request += '\xff\xff\xff\xff';
  connect_request += vip_address;
  connect_request += slave;
  connect_request += '\x00';
  connect_request += vip_address;
  connect_request += '\x00\x00';
  vip_send(soc:soc, channel_id:channel_id, payload:connect_request);

  connect_request = '\x20\x18';
  connect_request += direction;
  connect_request += seq;
  connect_request += ack;
  connect_request += '\x00\x00';
  connect_request += '\xff\xff\xff\xff';
  connect_request += vip_address;
  connect_request += slave;
  connect_request += '\x00';
  connect_request += vip_address;
  connect_request += '\x00\x00';
  vip_send(soc:soc, channel_id:channel_id, payload:connect_request);

  return TRUE;
}
