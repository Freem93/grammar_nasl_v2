# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# wins.inc
#
# $Revision: 1.4 $

##
# Converts an ip address in raw format to a string (in big endian)
#
# @param str binary IP address to convert
# @return dotted decimal string representation of "str"
##
function _raw_to_address(str)
{
  return strcat(ord(str[0]),".",ord(str[1]),".",ord(str[2]),".",ord(str[3]));
}

##
# Converts an address in dotted-string format to a big endian integer
#
# @param address dotted decimal IP address to convert
# @return binary representation of "address""
##
function _address_to_raw(address)
{
  address = split(address,sep:".",keep:0);
  return raw_string(int(address[0])) + raw_string(int(address[1])) + raw_string(int(address[2])) + raw_string(int(address[3]));
}

##
# remove padding from a netbios name
#
# this function removes trailing padding (spaces and low ASCII characters) from a netbios name
#
# @param name netbios name
# @return netbios name with the padding stripped
##
function _wins_clean_name(name)
{
  local_var i;

  for(i = strlen(name) - 1; i >= 0; i--)
  {
    if(ord(name[i]) > 0x20)
      return substr(name, 0, i);
  }
  return '';
}

##
# Send a WINS request and receive/return the reply. 
#
# @param s       The socket.
# @param context The context id - 0 for wins_start_association, and the return value
#                of wins_start_association for everything else.
# @param type    The message type - 0 for wins_start_association, 1 for
#                wins_stop_association, and 3 for everything else.
# @param data    The data packet - varies depending on packet type. 
#
# @return response data in a hash with the following keys: opcode, context, type, data
##
function _wins_send_recv(s, context, type, data)
{
  local_var request, r, length;

  # Create the request
  request = mkdword(0x00007800) + # opcode (supposed to be 0 in protocol, but only 0x00007800 works in practice)
            mkdword(context) +
            mkdword(type) +
            data;

  # Prepend the length
  request = mkdword(strlen(request)) + request;

  # Send it
  send(socket:s, data:request);

  # There's no response to stop_assocation packets
  if(type == 2)
    return NULL;

  # Receive the length
  r = recv(socket:s, length:4, min:4);
  if(isnull(r) || strlen(r) != 4)
    return NULL;

  # Get the length and make sure it's a sane size
  length = getdword(blob:r, pos:0);
  if(length > 5 * 1024 * 1024)
    return NULL;
  else if(length < 0)
    return NULL;
  else if(length <= 0x0c)
    return NULL;

  # Receive the rest of the packet
  r = recv(socket:s, length:length, min:length);
  if(isnull(r) || strlen(r) != length)
    return NULL;

  # Parse and return the rest of the packet
  return make_array('opcode',  getdword(blob:r, pos:0x00),
                    'context', getdword(blob:r, pos:0x04),
                    'type',    getdword(blob:r, pos:0x08),
                    'data',    substr(r, 0x0c));
}

##
# This is the first message sent in a WINS connection. It returns the
# context_id, which is sent to the remainder of the functions.
#
# @param s The socket.
#
# @return The context_id for this connection.
##
function wins_start_association(s)
{
  local_var request, response;

  # start_association requires a context id (that doesn't matter, as long as
  # it's 0x40 or below) and a version number (which has to be 5.2)
  request = mkdword(0x00000012) + # context
            mkword(0x0002) + # minor version
            mkword(0x0005) + # major version
            crap(length:0x15); # padding

  # Send the message
  response = _wins_send_recv(s:s, context:0, type:0, data:request);
  if(response['type'] != 1)
    return NULL;

  # All we really care about is the context - that's the first DWORD
  # value - the rest is padding (which is actually uninitialized stack data)
  return getdword(blob:response['data'], pos:0x00);
}

##
# This is the last message sent to a WINS host - there is no response (it
# closes the connection immediately). This isn't necessary, but is polite
# to use.
#
# @param s       The socket.
# @param context The context id returned by start_association.
##
function wins_stop_association(s, context)
{
  local_var request;

  # All we send to stop the connection is a single dword - 0 means no error
  # and 4 means there was an error. 
  request = mkdword(0x00000000) + # No error (4 = error)
            crap(length:0x18);    # Padding

  # We don't get a response from this
  _wins_send_recv(s:s, context:context, type:2, data:request);
}

##
# Request a list of "record owners" that the remote WINS server knows about.
# This is generally a list of other WINS hosts that each have one or more  
# records.
#
# @param s       The socket.
# @param context The context id returned by start_association.
# 
# @return A list of owner records - each record is an array containing
#         the ip address (as a dotted string), as well as four version
#         fields representing two 64-bit version numbers (max_version_hi,
#         max_version_lo, min_version_hi, min_version_lo. This list can be
#         passed directly to wins_name_records_request().
##
function wins_owner_records_request(s, context)
{
  local_var request, response, number_of_owners, data, pos, rplopcode, i, owner;

  # We send the rplopcode 0 (it's actually three reserved bytes then a one-byte
  # opcode)
  request = mkdword(0x00000000);

  # Send the request
  response = _wins_send_recv(s:s, context:context, type:3, data:request);
  if(response['type'] != 3)
    return NULL;

  data = response['data'];
  pos = 0;

  # Make sure the opcode is what we expect
  rplopcode = getdword(blob:data, pos:pos) & 0x000000FF;
  pos = pos + 4;
  if(rplopcode != 0x01)
    return NULL;

  # Get the number of records that'll be found in the message
  number_of_owners = getdword(blob:data, pos:pos);
  pos = pos + 4;
  if(number_of_owners > 0xFFFFFF)
    return NULL;

  # Loop over the list
  response = make_list();
  for(i = 0; i < number_of_owners; i++)
  {
    if(strlen(data) < pos + (4 * 6))
      return NULL; # Malformed packet

    # Extract the address and the two 64-bit version numbers
    owner = make_array();
    owner['address'] = _raw_to_address(str:substr(data, pos, pos + 3));
    pos = pos + 4;

    owner['max_version_hi'] = getdword(blob:data, pos:pos);
    pos = pos + 4;

    owner['max_version_lo'] = getdword(blob:data, pos:pos);
    pos = pos + 4;

    owner['min_version_hi'] = getdword(blob:data, pos:pos);
    pos = pos + 4;

    owner['min_version_lo'] = getdword(blob:data, pos:pos);
    pos = pos + 4;

    # Reserved (we ignore)
    pos = pos + 4;

    response[max_index(response)] = owner;
  }

  return response;
}

##
# Request a list of name records from a WINS server belonging to a specific
# owner. Each owner stores record versions. The owners and versions can be
# obtained by calling wins_owner_records_request(). 
#
# @param s       The socket.
# @param context The context id returned by start_association.
# @param address The ip address of the 'owner'.
# @param min_version_lo Part of the version information.
# @param min_version_hi Part of the version information.
# @param max_version_lo Part of the version information.
# @param max_version_hi Part of the version information.
# @param wins_owner_records The table of owners/versions returned by 
#                wins_owner_records_request().
#
# @return An array of the owner ip addresses, each element of which is an array
#         containing a number of fields, including 'address' (or 'addresses').
##
function wins_name_records_request(s, context, address, min_version_lo, min_version_hi, max_version_lo, max_version_hi)
{
  local_var request, response, result, i, j, data, rplopcode, number_of_records, pos, owner, entry_type, name_record, name_records, owner_address, member_address;

  # Create the body request based on the address and version from the owner-
  # request message
  request = mkdword(0x00000002) + # rplopcode
            _address_to_raw(address:address) +
            mkdword(max_version_hi) + mkdword(max_version_lo) +
            mkdword(min_version_hi) + mkdword(min_version_lo) +
            mkdword(0x00000000); # Reserved

  # Send the request
  response = _wins_send_recv(s:s, context:context, type:3, data:request);
  if(response['type'] != 3)
    return NULL;
  data = response['data'];

  # Verify that it returned the proper response 
  rplopcode = getdword(blob:data, pos:0);
  if(rplopcode != 3) 
    return NULL;

  # Get the number of records 
  number_of_records = getdword(blob:data, pos:4);

  # Loop over the records, extract their data, and add it to the table 
  name_records = make_list(); 
  pos = 8;
  for(i = 0; i < number_of_records; i++)
  {
    # Make sure we have enough bytes to get to the name
    if(strlen(data) < pos + 4)
      return NULL; # Malformed packet

    name_record = make_array();

    name_record['name_length'] = getdword(blob:data, pos:pos);
    pos = pos + 4;

    # Check if the name is actually there
    if(strlen(data) < pos + name_record['name_length'] + 4)
      return NULL; # Malformed packet

    name_record['name'] = _wins_clean_name(name:substr(data, pos, pos + name_record['name_length'] - 1));
    pos = pos + name_record['name_length'];
    # Ensure position ends up on a 4-byte boundary (add 4 if it's already on one)
    pos = pos + (4 - (pos % 4));

    # Re-check the length after reading the name
    if(strlen(data) < pos + 24)
      return NULL; # Malformed packet

    name_record['flags'] = getdword(blob:data, pos:pos) & 0x000000FF;
    pos = pos + 4;

    name_record['group'] = (getdword(blob:data, pos:pos) >> 24) & 0x000000FF;
    pos = pos + 4;

    name_record['version_hi'] = getdword(blob:data, pos:pos);
    name_record['version_lo'] = getdword(blob:data, pos:pos+4);
    pos = pos + 8;

    # Get the entry type from the flags
    entry_type = (name_record['flags'] & 0x03);

    # If the entry type is 0 (unique name) or 1 (normal group), it's an ipv4 address
    if(entry_type == 0x00 || entry_type == 0x01)
    {
      name_record['address'] = _raw_to_address(str:substr(data, pos, pos+3));
      pos = pos + 4;
    }
    else # Otherwise, it's a list of addresses
    {
      name_record['address_count'] = (getdword(blob:data, pos:pos) >> 24) & 0x000000FF;
      pos = pos + 4;
      name_record['addresses'] = make_list();
      for(j = 0; j < name_record['address_count']; j++)
      {
        owner_address = _raw_to_address(str:substr(data, pos, pos+3));
        pos = pos + 4;
        member_address = _raw_to_address(str:substr(data, pos, pos+3));
        pos = pos + 4;

        name_record['addresses'] = make_list(name_record['addresses'], member_address);
      }
    }

    name_record['reserved'] = getdword(blob:data, pos:pos);
    pos = pos + 4;

    name_records[max_index(name_records)] = name_record;
  }

  return name_records;
}
