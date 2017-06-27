###
# -*- Fundamental -*-
#
# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# See the following licenses for details :
#  http://www.nessus.org/plugins/RegisteredFeed.pdf
#  http://www.nessus.org/plugins/DirectFeed.pdf
#  http://www.nessus.org/plugins/DirectFeedCommercial.pdf
#
#
# @NOGPL@
#
# corba_func.inc
# $Revision: 1.3 $
###


# Byte order.
CDR_BYTE_ORDER_BIG_ENDIAN    = 0;
CDR_BYTE_ORDER_LITTLE_ENDIAN = 1;
CDR_BYTE_ORDER_DEFAULT       = CDR_BYTE_ORDER_LITTLE_ENDIAN;

# GIOP Message Types
GIOP_MSGTYPE_REQUEST         = 0;
GIOP_MSGTYPE_REPLY           = 1;
GIOP_MSGTYPE_CANCELREQUEST   = 2;
GIOP_MSGTYPE_LOCATEREQUEST   = 3;
GIOP_MSGTYPE_LOCATEREPLY     = 4;
GIOP_MSGTYPE_CLOSECONNECTION = 5;
GIOP_MSGTYPE_MESSAGEERROR    = 6;
GIOP_MSGTYPE_FRAGMENT        = 7;

# GIOP Reply Statuses
GIOP_REPLYSTATUS_NO_EXCEPTION          = 0;
GIOP_REPLYSTATUS_USER_EXCEPTION        = 1;
GIOP_REPLYSTATUS_SYSTEM_EXCEPTION      = 2;
GIOP_REPLYSTATUS_LOCATION_FORWARD      = 3;
GIOP_REPLYSTATUS_LOCATION_FORWARD_PERM = 4;
GIOP_REPLYSTATUS_NEEDS_ADDRESSING_MODE = 5;

# IOR Profiles.
TAG_INTERNET_IOP        = 0;
TAG_MULTIPLE_COMPONENTS = 1;
TAG_SCCP_IOP            = 2;

# Component ID Tags.
TAG_ORB_TYPE                      = 0;
TAG_CODE_SETS                     = 1;
TAG_POLICIES                      = 2;
TAG_ALTERNATE_IIOP_ADDRESS        = 3;
TAG_COMPLETE_OBJECT_KEY           = 5;
TAG_ENDPOINT_ID_POSITION          = 6;
TAG_LOCATION_POLICY               = 12;
TAG_ASSOCIATION_OPTIONS           = 13;
TAG_SEC_NAME                      = 14;
TAG_SPKM_1_SEC_MECH               = 15;
TAG_SPKM_2_SEC_MECH               = 16;
TAG_KerberosV5_SEC_MECH           = 17;
TAG_CSI_ECMA_Secret_SEC_MECH      = 18;
TAG_CSI_ECMA_Hybrid_SEC_MECH      = 19;
TAG_SSL_SEC_TRANS                 = 20;
TAG_CSI_ECMA_Public_SEC_MECH      = 21;
TAG_GENERIC_SEC_MECH              = 22;
TAG_FIREWALL_TRANS                = 23;
TAG_SCCP_CONTACT_INFO             = 24;
TAG_JAVA_CODEBASE                 = 25;
TAG_TRANSACTION_POLICY            = 26;
TAG_FT_GROUP                      = 27;
TAG_FT_PRIMARY                    = 28;
TAG_FT_HEARTBEAT_ENABLED          = 29;
TAG_MESSAGE_ROUTERS               = 30;
TAG_OTS_POLICY                    = 31;
TAG_INV_POLICY                    = 32;
TAG_CSI_SEC_MECH_LIST             = 33;
TAG_NULL_TAG                      = 34;
TAG_SECIOP_SEC_TRANS              = 35;
TAG_TLS_SEC_TRANS                 = 36;
TAG_ACTIVITY_POLICY               = 37;
TAG_RMI_CUSTOM_MAX_STREAM_FORMAT  = 38;
TAG_DCE_STRING_BINDING            = 100;
TAG_DCE_BINDING_NAME              = 101;
TAG_DCE_NO_PIPES                  = 102;
TAG_DCE_SEC_MECH                  = 103;
TAG_INET_SEC_TRANS                = 123;


global_var _cdr_byte_order;


##
# Gets byte ordering
#
# @remark The actual values are different from those in [byte_func.inc].
# @return An integer representing the byte ordering.
##
function cdr_get_byte_order()
{
  return _cdr_byte_order;
}


##
# Sets byte ordering.
#
# @anonparam byte_order new byte ordering
##
function cdr_set_byte_order()
{
  _cdr_byte_order = _FCT_ANON_ARGS[0];
}


##
# Extracts a char / octet / boolean from a blob.
#
# @param blob blob to extract byte from
# @param pos index in 'blob' where the value should be extracted from
#
# @return a byte value.
##
function cdr_unmarshal_octet(blob, pos)
{
  return ord(blob[pos]);
}


##
# Extracts a number of a given size from a blob starting at offset pos.
#
# @param blob blob to extract number from
# @param pos index in 'blob' where the value should be extracted from
# @param size number of bytes to extract
# @remark the return value is a 32-bit integer. if size > 4, the desired
#         data will not be returned
#
# @return a number if successful;
#         NULL otherwise.
##
function cdr_unmarshal_num(blob, pos, size)
{
  local_var byte, i, num;

  if (isnull(size) || strlen(substr(blob, pos)) < size) return NULL;

  num = 0;
  for (i=0; i<size; i++)
  {
    byte = cdr_unmarshal_octet(blob:blob, pos:pos+i);
    if (CDR_BYTE_ORDER_LITTLE_ENDIAN == _cdr_byte_order) num += byte << 8*i;
    else num += byte << 8*(size-i-1);
  }

  return num;
}


##
# Extracts a short / ushort from a blob.
#
# @param blob blob to extract short from
# @param pos index in 'blob' where the short should be extracted from
#
# @return a number if successful;
#         NULL otherwise.
##
function cdr_unmarshal_short(blob, pos)
{
  return cdr_unmarshal_num(blob:blob, pos:pos, size:2);
}


##
# Extracts a long / ulong from a blob.
#
# @param blob blob to extract long from
# @param pos index in 'blob' where the long should be extracted from
#
# @return a number if successful;
#         NULL otherwise.
##
function cdr_unmarshal_long(blob, pos)
{
  return cdr_unmarshal_num(blob:blob, pos:pos, size:4);
}


##
# Extracts a string from a blob.
#
# @param blob blob to extract string from
# @param pos index in 'blob' where the string should be extracted from. this index
#            should point to the 4 byte length that preceeds the string to be extracted
#
# @return a string if successful;
#         NULL otherwise.
##
function cdr_unmarshal_string(blob, pos)
{
  local_var len;

  len = cdr_unmarshal_long(blob:blob, pos:pos);
  pos += 4;

  return substr(blob, pos, pos+len-2);
}


##
# Extracts a wide string from a blob.
#
# @param blob blob to extract wide string from
# @param pos index in 'blob' where the wide string should be extracted from. this index
#            should point to the 4 byte length that preceeds the wide string to be extracted
#
# @return a wide string if successful;
#         NULL otherwise.
##
function cdr_unmarshal_wstring(blob, pos)
{
  local_var len, s;

  len = cdr_unmarshal_long(blob:blob, pos:pos);
  pos += 4;
  len *= 2;

  return substr(blob, pos, pos+len-3);
}


##
# Marshals a char / octet / boolean and appends result to the blob.
#
# @param blob blob to update
# @param num value to append to 'blob'
#
# @return updated blob.
##
function cdr_marshal_octet(blob, num)
{
  return raw_string(blob, num);
}


##
# Marshals a number of a given size and appends result to the blob.
#
# @param blob blob to update
# @param num integer value to append to 'blob'
# @param size size of 'num' in bytes
# @param this function can only append up to 32 bits at a time.
#        specifying a 'size' of greater than 4 bytes will have unintended consequences
#
# @return updated blob.
##
function cdr_marshal_num(blob, num, size)
{
  local_var i, l;

  l = strlen(blob);
  if (l % size) blob+= crap(data:raw_string(0), length:(size - (l % size)));

  if (CDR_BYTE_ORDER_LITTLE_ENDIAN == _cdr_byte_order)
  {
    for (i=0; i<size; i++)
      blob += raw_string((num >> (i*8)) & 0xff);
  }
  else
  {
    for (i=size-1; i<=0; i--)
      blob += raw_string((num >> (i*8)) & 0xff);
  }

  return blob;
}


##
# Marshals a short / ushort and appends result to the blob.
#
# @param blob blob to update
# @param num short to append to 'blob'
#
# @return updated blob.
##
function cdr_marshal_short(blob, num)
{
  return cdr_marshal_num(blob:blob, num:num, size:2);
}


##
# Marshals a long / ulong and appends result to the blob.
#
# @param blob blob to update
# @param num long to append to 'blob'
#
# @return updated blob.
##
function cdr_marshal_long(blob, num)
{
  return cdr_marshal_num(blob:blob, num:num, size:4);
}


##
# Marshals a string and appends result to the blob.
#
# @param blob blob to update
# @param str string to append to 'blob'
#
# @return updated blob.
##
function cdr_marshal_string(blob, str)
{
  local_var len;

  if (str[strlen(str)-1] != raw_string(0)) str += raw_string(0);
  len = strlen(str);

  return (cdr_marshal_num(blob:blob, num:len, size:4) + str);
}


##
# Marshals a wide string and appends result to the blob.
#
# @param blob blob to update
# @param str wide string to append to 'blob'
#
# @return updated blob.
##
function cdr_marshal_wstring(blob, str)
{
  local_var len;

  if (str[strlen(str)-1] != raw_string(0)) str += raw_string(0) + raw_string(0);
  len = strlen(str) / 2;

  return (cdr_marshal_num(blob:blob, num:len, size:4) + str);
}


##
# Converts an IOR string into an IOR.
#
# @param str IOR string to convert
#
# @return marshalled IOR as a blob if successful;
#         NULL otherwise.
##
function ior_destringify(str)
{
  local_var i, j, ior;

  # Sanity check.
  if (
    strlen(str) < 4 || 
    strlen(str) % 2 || 
    toupper(substr(str, 0, 3)) != 'IOR:'
  ) return NULL;

  ior = "";
  for (i=4; i<strlen(str); i+=2)
  {
    if(ord(str[i]) >= ord("0") && ord(str[i]) <= ord("9"))
      j = int(str[i]);
    else
      j = int((ord(tolower(str[i])) - ord("a")) + 10);

    j *= 16;
    if(ord(str[i+1]) >= ord("0") && ord(str[i+1]) <= ord("9"))
      j += int(str[i+1]);
    else
      j += int((ord(tolower(str[i+1])) - ord("a")) + 10);

    ior += raw_string(j);
  }

  return ior;
}


##
# Extracts an IOR from a blob.
#
# @param ior IOR blob
#
# @return an IOR object if successful;
#         NULL otherwise.
##
function ior_unmarshal(ior)
{
  local_var i, l, nprofiles, obj, p, profile_id, type_id;

  cdr_set_byte_order(cdr_unmarshal_octet(blob:ior, pos:0) & 1);

  p = 4;
  type_id = cdr_unmarshal_string(blob:ior, pos:p);
  if (isnull(type_id)) return NULL;
  p += 4 + strlen(type_id) + 1;
  obj['type_id'] = type_id;

  if (p % 4) p += 4 - (p % 4);
  nprofiles = cdr_unmarshal_long(blob:ior, pos:p);
  p += 4;
  obj['nprofiles'] = nprofiles;
  for (i=1; i<=nprofiles; i++)
  {
    if (p % 4) p += 4 - (p % 4);
    profile_id = cdr_unmarshal_long(blob:ior, pos:p);
    p += 4;
    obj['profile_'+i] = profile_id;

    if (p % 4) p += 4 - (p % 4);
    l = cdr_unmarshal_long(blob:ior, pos:p);
    p += 4;
    if (l)
    {
      obj['profile_'+i+'_data'] = substr(ior, p, p+l-1);
      p += l;
    }
    else obj['profile_'+i+'_data'] = "";
  }

  return obj;
}


##
# Marshals a GIOP message object.
#
# @param giop GIOP message object to marshall
#
# @return a blob if successful;
#         NULL otherwise.
##
function giop_marshal_message(giop)
{
  local_var bytes, v;

  bytes = "GIOP";

  v = split(giop['version'], sep:".", keep:FALSE);
  bytes = cdr_marshal_octet(blob:bytes, num:int(v[0]));
  bytes = cdr_marshal_octet(blob:bytes, num:int(v[1]));

  if (int(v[0]) == 1 && int(v[1]) == 0)
    bytes = cdr_marshal_octet(blob:bytes, num:giop['byte_order']);
  else
    bytes = cdr_marshal_octet(blob:bytes, num:giop['flags']);

  bytes = cdr_marshal_octet(blob:bytes, num:giop['type']);
  bytes = cdr_marshal_long(blob:bytes, num:strlen(giop['msg']));
  bytes += giop['msg'];

  return bytes;
}


##
# Marshals a GIOP request object.
#
# @param req GIOP request object to marshal
#
# @return a blob if successful;
#         NULL otherwise.
##
function giop_marshal_request(req)
{
  local_var bytes, giop;

  giop['version'] = req['version'];

  bytes = req['service_context_list'];
  bytes = cdr_marshal_long(blob:bytes, num:req['request_id']);
  bytes = cdr_marshal_octet(blob:bytes, num:req['response_expected']);
  bytes = cdr_marshal_long(blob:bytes, num:strlen(req['object_key']));
  bytes += req['object_key'];
  bytes = cdr_marshal_string(blob:bytes, str:req['operation']);
  bytes = cdr_marshal_long(blob:bytes, num:strlen(req['requesting_principal']));
  bytes += req['requesting_principal'];

  if (req['version'] == "1.0") giop['byte_order'] = CDR_BYTE_ORDER_DEFAULT;
  else giop['flags'] = CDR_BYTE_ORDER_DEFAULT;
  giop['type'] = GIOP_MSGTYPE_REQUEST;
  giop['msg'] = bytes;

  return giop_marshal_message(giop:giop);
}


##
# Extracts a GIOP message from a blob.
#
# @param str blob to extract GIOP message from
#
# @return A GIOP message object if successful;
#         NULL otherwise.
##
function giop_unmarshal_message(str)
{
  local_var giop, l, p, v;

  # Sanity check.
  if (
    strlen(str) < 4 || 
    toupper(substr(str, 0, 3)) != 'GIOP'
  ) return NULL;

  p = 4;
  v[0] = cdr_unmarshal_octet(blob:str, pos:p++);
  v[1] = cdr_unmarshal_octet(blob:str, pos:p++);
  giop['version'] = string(v[0], ".", v[1]);

  cdr_set_byte_order(cdr_unmarshal_octet(blob:str, pos:p) & 1);
  ++p;

  giop['type'] = cdr_unmarshal_octet(blob:str, pos:p);
  ++p;

  if (p % 4) p += 4 - (p % 4);
  l = cdr_unmarshal_long(blob:str, pos:p);
  p += 4;
  if (l)
  {
    giop['msg'] = substr(str, p, p+l-1);
    p += l;
  }
  else giop['msg'] = "";


  return giop;
}


##
# Extracts a GIOP reply from a blob.
#
# @param str blob to extract GIOP reply from
#
# @return A GIOP reply object if successful;
#         NULL otherwise.
##
function giop_unmarshal_reply(str)
{
  local_var giop, l, msg, p, reply, v;

  giop = giop_unmarshal_message(str:str);
  if (isnull(giop)) return NULL;
  if (giop['type'] != GIOP_MSGTYPE_REPLY) return NULL;

  v = giop['version'];
  msg = giop['msg'];

  # Reply header.
  p = 0;
  if (v == '1.0' || v == '1.1')
  {
    l = cdr_unmarshal_long(blob:msg, pos:p);
    p += 4;
    if (l)
    {
      reply['service_context_list'] = substr(msg, p, p+l-1);
      p += l;
    }
    else reply['service_context_list'] = "";

    if (p % 4) p += 4 - (p % 4);
    reply['request_id'] = cdr_unmarshal_long(blob:msg, pos:p);
    p += 4;

    if (p % 4) p += 4 - (p % 4);
    reply['reply_status'] = cdr_unmarshal_long(blob:msg, pos:p);
    p += 4;

    reply['body'] = substr(msg, p);
  }
  else
  {
    if (p % 4) p += 4 - (p % 4);
    reply['request_id'] = cdr_unmarshal_long(blob:msg, pos:p);
    p += 4;

    if (p % 4) p += 4 - (p % 4);
    reply['reply_status'] = cdr_unmarshal_long(blob:msg, pos:p);
    p += 4;

    l = cdr_unmarshal_long(blob:msg, pos:p);
    p += 4;
    if (l)
    {
      reply['service_context_list'] = substr(msg, p, p+l-1);
      p += l;
    }
    else reply['service_context_list'] = "";

    if (p % 8) p += 8 - (p % 8);
    reply['body'] = substr(msg, p);
  }

  return reply;
}


##
# Extracts an IIOP Profile from a blob.
#
# @param str blob to extract IIOP Profile from
#
# @return an IIOP Profile object if successful;
#         NULL otherwise.
##
function iiop_unmarshal_profile(str)
{
  local_var component_id, host, i, l, n, p, port, profile, ver_maj, ver_min;

  cdr_set_byte_order(cdr_unmarshal_octet(blob:str, pos:0) & 1);

  ver_maj = cdr_unmarshal_octet(blob:str, pos:1);
  ver_min = cdr_unmarshal_octet(blob:str, pos:2);
  profile['version'] = string(ver_maj, ".", ver_min);

  p = 4;
  host = cdr_unmarshal_string(blob:str, pos:p);
  if (isnull(host)) return NULL;
  p += 4 + strlen(host) + 1;
  profile['host'] = host;

  if (p % 4) p += 4 - (p % 4);
  port = cdr_unmarshal_short(blob:str, pos:p);
  p += 2;
  profile['port'] = port;

  if (p % 4) p += 4 - (p % 4);
  l = cdr_unmarshal_long(blob:str, pos:p);
  p += 4;
  if (l)
  {
    profile['object_key'] = substr(str, p, p+l-1);
    p += l;
  }
  else profile['object_key'] = "";

  if (ver_maj == 1 && ver_min > 0)
  {
    if (p % 4) p += 4 - (p % 4);
    n = cdr_unmarshal_long(blob:str, pos:p);
    # nb: abort if we have too many profiles.
    if (n >= 1024) return NULL;
    p += 4;
    profile['ncomponents'] = n;
    for (i=1; i<=n; i++)
    {
      if (p % 4) p += 4 - (p % 4);
      component_id = cdr_unmarshal_long(blob:str, pos:p);
      p += 4;
      profile['taggedcomponent_'+i] = component_id;

      if (p % 4) p += 4 - (p % 4);
      l = cdr_unmarshal_long(blob:str, pos:p);
      p += 4;
      if (l)
      {
        profile['taggedcomponent_'+i+'_data'] = substr(str, p, p+l-1);
        p += l;
      }
      else profile['taggedcomponent_'+i+'_data'] = "";
    }
  }

  return profile;
}
