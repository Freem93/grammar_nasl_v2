#TRUSTED 20cd56d5bef87cbf79cabe251626e82d1153fac4554bf46b24819a291a661bc2cd6c690b8d541a9b540c705f4a89d8c1e8ed8f9556d79ce6710b3ee2fe802a0bc74d7b7b42236e94f3d2aa6f30a89e560865a7972faf9c234dabe485e1f84ad50cb7da37d8dd5895767d7cc2a19134d8c81bb2fb07496defdb765f3e1a4f1b952a347f778966ab99b7775c2951c55580a0f19b5992ff0142fefb16c51e4be2178de8260654f75379edf97a1f0b5079c0080352aaf8d2ccc8c4e6af26cbd60ff7bb342d45da10f0e408795775262e2b783e1f47768cf147ca70dcbabc1b4f18d4b79f21b0563d33d22bcb587226eb877804af0ce20f0df8b28d48bcb99dc16e01a04ec730f328beb2cd3f24430deef37c883bdaf2801920199735e873f0bc47861f7e9f1e02e731251eec3bc31b2828bcb67a2e62bcf8ff05f7a7cf797af6269a686739ed691542d63628d285d73ac00601692c84c31474684e4871cb2f36d2981897b823fe40f314e2f6fcb6921331ce2dbaac5bdf49f2a28b6f3664914ad1cfd9ae78adb4158e9251fbed7306122690d023a9f005d26fe7b487093a7609235d898854a8c6dfa7a1018903d56c51d17ade0a59039bfdf50e3d912f0f1437e88784509b4cea30075e265dad0dd7515dbe3424668b32009b222bde6231a317977754f6c2ba744b187a0b321524faac09354087e5a7d74f3ea94fd8c6ed1e2b6714
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# snmp_func.inc
# Revision: 1.28
#

include( "byte_func.inc" );
include( "crypto_func.inc" );

global_var snmp_request_id, SNMP_VERSION, end_mib;
global_var msg_id, auth_engine_id, auth_engine_boots, auth_engine_time;

snmp_request_id = rand();       # Should not be predictable
end_mib = FALSE;

auth_engine_id    = '';
auth_engine_boots = 0;
auth_engine_time  = 0;
creds = make_list( '', '', '', '', '', '' );

SNMP_VERSION = get_kb_item ("SNMP/version");
_SNMP_VERSION = NULL;
if (isnull(SNMP_VERSION))
  SNMP_VERSION = 0; # snmpv1

function init_snmp ()
{
 end_mib = FALSE;
}

MSG_MAX_SIZE = 4096;

MSG_AUTHENTICATED_FLAG  = 0x01;
MSG_ENCRYPTED_FLAG      = 0x02;
MSG_REPORTABLE_FLAG     = 0x04;

USM_SECURITY_MODEL = 0x03;

EMPTY_AUTH_STRING = crap( data:raw_string( 0x00 ), length:12 );
IPAD = crap( data:raw_string( 0x36 ), length:64 );
OPAD = crap( data:raw_string( 0x5c ), length:64 );
PEPPER = rand();  # to be loaded at boot as per rfc3414, section 8.1.1.1.1

# Fake out a 64 bit random number by picking an outer random 32 bit and packing it backwards.
set_byte_order( BYTE_ORDER_LITTLE_ENDIAN );
PEPP64 = mkdword( rand() );  # for faking a 64 bit random number
set_byte_order( BYTE_ORDER_BIG_ENDIAN );

USM_LEVEL_AUTH_PRIV       = 0x03;   # authPriv
USM_LEVEL_AUTH_NO_PRIV    = 0x01;   # authNoPriv
USM_LEVEL_NO_AUTH_NO_PRIV = 0x00;   # noAuthNoPriv

OP_GET_REQUEST      = 0xa0;
OP_GET_NEXT_REQUEST = 0xa1;
OP_SET_REQUEST      = 0xa3;
OP_GET_BULK_REQUEST = 0xa5;

TYPE_INTEGER = 0x02;
TYPE_OCTET_STRING = 0x04;
TYPE_NULL = 0x05;

SYS_DESCR = '1.3.6.1.2.1.1.1.0';

USM_STATS_UNKNOWN_USER_NAMES  = '1.3.6.1.6.3.15.1.1.3.0';
USM_STATS_UNKNOWN_ENGINE_IDS  = '1.3.6.1.6.3.15.1.1.4.0';
USM_STATS_WRONG_DIGESTS       = '1.3.6.1.6.3.15.1.1.5.0';
USM_STATS_DECRYPTION_ERRORS   = '1.3.6.1.6.3.15.1.1.6.0';

#---------------------------------------------------------#
# Function    : ber_length                                #
# Description : return raw ber length of data             #
#---------------------------------------------------------#

function ber_length (data)
{
 local_var tmp, length, len;

 length = NULL;
 len = strlen (data);

 if (len == 0)
   return raw_string (0);

 while (len != 0)
 {
  length = raw_string (len % 256) + length;
  len = len / 256;
 }

 if ((strlen (length) > 1) || ((strlen(length) == 1) && (ord(length[0]) > 127)))
   length = raw_string (128 + strlen (length)) + length;

 return length;
}


#---------------------------------------------------------#
# Function    : ber_encode                                #
# Description : Return ber encoded data                   #
#---------------------------------------------------------#

function ber_encode (tag,data)
{
 return raw_string (tag) + ber_length(data:data) + data;
}


#---------------------------------------------------------#
# Function    : ber_put_int                               #
# Description : Return ber encoded INTEGER                #
#---------------------------------------------------------#

function ber_put_int (i)
{
 local_var val,j,tmp;

 if (isnull (i))
   return NULL;

 val[0] = i & 255;
 val[1] = (i>>8)  & 255;
 val[2] = (i>>16) & 255;
 val[3] = (i>>24) & 255;

 j = 3;
 while ((val[j] == 0) && (j != 0))
   j--;

 # Integer encoding was broken.  See example: http://luca.ntop.org/Teaching/Appunti/asn1.html
 # there should be a more elegant implementation
 tmp = NULL;
 if ( ( ( i > 127 ) && ( i < 0xff ) ) || ( ( i > 0x0eff ) && ( i < 0xffff ) ) )
  tmp = raw_string( 0x00 );

 while (j != 0)
 {
  tmp += raw_string (val[j]);
  j--;
 }

 tmp += raw_string (val[j]);

 return ber_encode (tag:0x02, data:tmp);
}


#---------------------------------------------------------#
# Function    : ber_put_octet_string                      #
# Description : Return ber encoded OCTET STRING           #
#---------------------------------------------------------#

function ber_put_octet_string (string)
{
 return ber_encode (tag:0x04, data:string);
}


#---------------------------------------------------------#
# Function    : ber_put_get_pdu                           #
# Description : Return ber encoded GetRequestPDU          #
#---------------------------------------------------------#

function ber_put_get_pdu (pdu)
{
 return ber_encode (tag:OP_GET_REQUEST, data:pdu);
}


#---------------------------------------------------------#
# Function    : ber_put_get_next_pdu                      #
# Description : Return ber encoded GetRequestNextPDU      #
#---------------------------------------------------------#

function ber_put_get_next_pdu (pdu)
{
 return ber_encode (tag:OP_GET_NEXT_REQUEST, data:pdu);
}

#---------------------------------------------------------#
# Function    : ber_put_set_pdu                           #
# Description : Return ber encoded SetRequestPDU          #
#---------------------------------------------------------#

function ber_put_set_pdu (pdu)
{
 return ber_encode (tag:OP_SET_REQUEST, data:pdu);
}

#---------------------------------------------------------#
# Function    : ber_put_get_bulk_pdu                           #
# Description : Return ber encoded GetBulkRequestPDU          #
#---------------------------------------------------------#

function ber_put_get_bulk_pdu (pdu)
{
 return ber_encode (tag:OP_GET_BULK_REQUEST, data:pdu);
}

#---------------------------------------------------------#
# Function    : ber_put_null                              #
# Description : Return ber encoded NULL                   #
#---------------------------------------------------------#

function ber_put_null ()
{
 return ber_encode (tag:0x05, data:NULL);
}


#---------------------------------------------------------#
# Function    : ber_put_oid                               #
# Description : Return ber encoded OID (string)           #
#               ex: "1.2.840.113554.1.2.2"                #
#---------------------------------------------------------#

function ber_put_oid (oid)
{
 local_var nums, num, enum, i, max, encoded;

 if (isnull (oid))
   return NULL;

 nums = split (oid, sep:".", keep:0);

 max = max_index (nums);
 if (max < 2)
   return NULL;

 # value1 x 40 + value2
 encoded = raw_string (40*int(nums[0]) + int(nums[1]));

 for (i=2; i < max; i++)
 {
  num = int(nums[i]);
  enum = raw_string (num % 128);
  num = num / 128;
  while (num != 0)
  {
   enum = raw_string (128 + (num%128)) + enum;
   num = num / 128;
  }
  encoded += enum;
 }

 # OID Tag = 0x06
 return ber_encode (tag:0x06, data:encoded);
}


#---------------------------------------------------------#
# Function    : ber_put_sequence                          #
# Description : Return ber encoded SEQUENCE               #
#---------------------------------------------------------#

function ber_put_sequence (seq)
{
 local_var encoded, max, i, j, val;

 max = max_index (seq);

 encoded = NULL;

 for (j=0; j < max; j++)
 {
  val = seq[j];
  if (!isnull(val))
  {
    encoded += val;
  }
 }

 # SEQUENCE Tag = 0x30
 return ber_encode (tag:0x30, data:encoded);
}


function _integer (i)
{
 local_var j,k,len;

 j = 0;
 len = strlen (i);

 for (k=0; k < len; k++)
 {
  j = j * 256 + ord(i[k]);
 }

 return j;
}


#---------------------------------------------------------#
# Function    : ber_decode                                #
# Description : Return ber decoded data                   #
#               [0] = code                                #
#               [1] = data                                #
#               [2] = next pos in buffer                  #
#---------------------------------------------------------#

function ber_decode (data, pos)
{
 local_var tmp, i, j, len, len2;

 if (isnull (data))
   return NULL;

 if (isnull (pos))
   j = 0;
 else
   j = pos;

 if (strlen(data) - j  < 2)
   return NULL;

 tmp[0] = ord(data[j]);
 j++;

 len = ord(data[j]);
 j++;
 if (len > 127)
 {
  len -= 128;
  if (strlen(data) - j < len)
    return NULL;

  len2 = _integer (i:substr (data, j, j + len - 1));
  j += len;
  len = len2;
 }

 if (strlen(data) - j < len)
   return NULL;

 tmp[1] = substr(data,j,j+len-1);
 tmp[2] = j + len;

 # tmp is a tuple of 3 elements ( the starting index position, the read value, and the total length)
 return tmp;
}


#---------------------------------------------------------#
# Function    : ber_decode_oid                            #
# Description : Return OID (string)                       #
#               ex: "1.2.840.113554.1.2.2"                #
#---------------------------------------------------------#

function ber_decode_oid (oid)
{
 local_var soid, i, val, len;

 if (strlen (oid) < 1)
   return NULL;

 soid = string (ord (oid[0]) / 40, ".", ord (oid[0]) % 40);

 len = strlen (oid);

 for (i = 1; i < len; i++)
 {
  val = 0;
  while (ord(oid[i]) >= 128)
  {
   val = ((ord(oid[i]) - 128) + val) * 128;
   i++;
  }
  val += ord (oid[i]);
  soid += string (".",val);
 }

 return soid;
}


#---------------------------------------------------------#
# Function    : ber_get_data                              #
# Description : Return ber decoded data                   #
#---------------------------------------------------------#

function ber_get_data (tag,data)
{
 local_var tmp;

 tmp = ber_decode (data:data);
 if (isnull (tmp) || (tmp[0] != tag))
   return NULL;

 return tmp[1];
}


#---------------------------------------------------------#
# Function    : ber_get_sequence                          #
# Description : Return der decoded sequence               #
#---------------------------------------------------------#

function ber_get_sequence (seq)
{
 local_var tmp,pos,i,ret,list, len;

 if (!seq)
   return NULL;

 list = ber_decode (data:seq);

 if (isnull(list) || (list[0] != 0x30))
   return NULL;

 list = list[1];

 tmp = NULL;
 tmp[0] = 0;

 pos = 0;
 i = 1;
 len = strlen (list);

 while (pos < len)
 {
  ret = ber_decode (data:list,pos:pos);
  if (isnull(ret))
    return NULL;

  ##### NOTE, this was tmp[i] = substr (list, pos, ret[2]), which led to duplication of the last character in the str
  tmp[i] = substr (list, pos, ret[2] - 1);
  tmp[0] = tmp[0] + 1;
  pos = ret[2];
  i++;
 }

 # tmp[ 0 ] is the count of the number of elements in tmp
 return tmp;
}


#---------------------------------------------------------#
# Function    : ber_response_pdu                          #
# Description : Return ber decoded response_pdu           #
#---------------------------------------------------------#

function ber_get_response_pdu (pdu)
{
 local_var tmp,pos,i,ret,list, len;

 if (!pdu)
   return NULL;

 list = ber_decode (data:pdu);
 # 0xA1 = SNMPv1 get next request
 # 0xA2 = SNMPv1 get response
 # 0xA8 = SNMPv3 report
 if (isnull(list) || ((list[0] != 0xA2) && (list[0] != 0xA1) && (list[0] != 0xA8)) )
   return NULL;

 list = list[1];

 tmp = NULL;
 tmp[0] = 0;

 pos = 0;
 i = 1;
 len = strlen (list);

 while (pos < len)
 {
  ret = ber_decode (data:list,pos:pos);
  if (isnull(ret))
    return NULL;

  #### POSSIBLE SAME ISSUE AS IN ber_get_sequence
  tmp[i] = substr (list, pos, ret[2] - 1);
  tmp[0] = tmp[0] + 1;
  pos = ret[2];
  i++;
 }

 return tmp;
}


#---------------------------------------------------------#
# Function    : ber_get_int                               #
# Description : Return ber decoded integer                #
#---------------------------------------------------------#

function ber_get_int (i)
{
 local_var tmp;

 tmp = ber_get_data (tag:0x02, data:i);
 if (isnull(tmp))
   return NULL;

 tmp = _integer (i:tmp);
 if (isnull(tmp))
   return NULL;

 return tmp;
}

function ber_get_addr (i)
{
 local_var tmp;

 tmp = ber_get_data (tag:0x40, data:i);
 if (isnull(tmp) || strlen(tmp) != 4)
   return NULL;

 return strcat(ord(tmp[0]), '.', ord(tmp[1]), '.', ord(tmp[2]), '.', ord(tmp[3]));
}


function ber_get_counter32 (i)
{
 local_var tmp;

 tmp = ber_get_data (tag:0x41, data:i);
 if (isnull(tmp))
   return NULL;

 tmp = _integer (i:tmp);
 if (isnull(tmp))
   return NULL;

 if (tmp < 0) {tmp += 2147483648; }
 return tmp;
}


#---------------------------------------------------------#
# Function    : ber_get_timeticks                         #
# Description : Return ber decoded time                   #
#---------------------------------------------------------#

function ber_get_timeticks (time)
{
 local_var tmp, ms, ss, mm, hh, dd;

 tmp = ber_get_data (tag:0x43, data:time);
 if (isnull(tmp))
   return NULL;

 if ((strlen(tmp) > 4) || (strlen(tmp) == 4 && ord(tmp[0]) > 0x80))
 {
  return string ("Time is too big to be decoded : 0x", hexstr(tmp), " ms");
 }

 tmp = _integer (i:tmp);
 if (isnull(tmp))
   return NULL;

 # convert to sec
 tmp = tmp / 1000;
 ss = tmp % 60;
 tmp = tmp / 60;
 mm = tmp % 60;
 tmp = tmp / 60;
 hh = tmp % 24;
 dd = tmp / 24;

 return string( dd, "d ", hh,"h ", mm, "m ", ss, "s" );
}


#---------------------------------------------------------#
# Function    : ber_get_octet_string                      #
# Description : Return ber decoded octet string           #
#---------------------------------------------------------#

function ber_get_octet_string (string)
{
 return ber_get_data (tag:0x04, data:string);
}


#---------------------------------------------------------#
# Function    : ber_get_oid                               #
# Description : Return ber decoded oid                    #
#---------------------------------------------------------#

function ber_get_oid (oid)
{
 local_var tmp;

 tmp = ber_get_data (tag:0x06, data:oid);
 if (!tmp)
   return NULL;

 tmp = ber_decode_oid (oid:tmp);
 if (!tmp)
   return NULL;

 return tmp;
}

####
#### snmp_exchange
#### Handle the putting to wire and reading from.
####
function snmp_exchange( socket, data, timeout, ret_err )
{
  send( socket:socket, data:data );
  return snmp_reply( socket:socket, timeout:timeout, ret_err:ret_err );
}

####
#### snmpv3_fail( reaseon )
#### Used for debug and to set the FAILED KB value to avoid potentially computationally expensive auth retrys
####
function snmpv3_fail( reason )
{
  #display( 'SNMPv3 FAILED: ', reason, '\n' );
  set_kb_item( name:"SNMP/v3/FAILED", value:TRUE );
  return NULL;
}

#---------------------------------------------------------#
# Function    : snmp_extract_reply                        #
# Description : Return ber decoded snmp reply value       #
#---------------------------------------------------------#

function snmp_extract_reply (rep)
{
 if (strlen(rep) < 2)
   return NULL;

 if (ord(rep[0]) == 0x02)
   return ber_get_int (i:rep);

 if (ord(rep[0]) == 0x40)
   return ber_get_addr(i: rep);

 if (ord(rep[0]) == 0x41)
   return ber_get_counter32 (i:rep);

 if (ord(rep[0]) == 0x04)
   return ber_get_octet_string (string:rep);

 if (ord(rep[0]) == 0x06)
   return ber_get_oid (oid:rep);

 if (ord(rep[0]) == 0x82)
 {
  end_mib = TRUE;
  return NULL;
 }

 if (ord(rep[0]) == 0x43)
   return ber_get_timeticks (time:rep);

 return NULL;
}

####
#### snmpv3_parse_header
#### Helper function for reading SNMPv3 header data.
####
function snmpv3_parse_header( head_blob )
{
  local_var head_seq, _msg_id, msg_flags, msg_sec_model;

  head_seq = ber_get_sequence( seq:head_blob );

  if  ( head_seq[ 0 ] != 4 )
    return NULL;

  _msg_id       = ber_get_int( i:head_seq [ 1 ] );
  msg_flags     = ber_get_octet_string( string:head_seq[ 3 ] );
  msg_sec_model = ber_get_int( i:head_seq [ 4 ] );

  if ( ( _msg_id != msg_id ) || ( msg_sec_model != USM_SECURITY_MODEL ))
    return NULL;
  return msg_flags;
}

####
#### snmpv3_parse_auth_reponse
#### Parse out authoritative data from the response.  If we don't have the data, update our global values,
#### otherwise, validate the data.
function snmpv3_parse_authoritative( auth_blob )
{
  local_var msg_auth_engine_id, msg_auth_engine_boots, msg_auth_engine_time;
  local_var msg_user_name, msg_authent_params, msg_privacy_params, ret, auth_data_seq;

  auth_data_seq = ber_get_sequence( seq:ber_get_octet_string( string:auth_blob ) );

  msg_auth_engine_id     = ber_get_octet_string( string:auth_data_seq [ 1 ] );
  msg_auth_engine_boots  = ber_get_int( i:auth_data_seq [ 2 ] );
  msg_auth_engine_time   = ber_get_int( i:auth_data_seq [ 3 ] );
  msg_user_name          = ber_get_octet_string( string:auth_data_seq [ 4 ] );
  msg_authent_params     = ber_get_octet_string( string:auth_data_seq [ 5 ] );
  msg_privacy_params     = ber_get_octet_string( string:auth_data_seq [ 6 ] );

  # If we don't have any part of this data, set it all.  Possibily redundent, probably always all or nothing.
  # http://www.ietf.org/rfc/rfc3414.txt Section 2.3
  if( ( ! auth_engine_id ) || ( ! auth_engine_boots  ) || ( !  auth_engine_time  ) )
  {
    auth_engine_id    = msg_auth_engine_id;
    auth_engine_boots = msg_auth_engine_boots;
    auth_engine_time  = msg_auth_engine_time;
  }
  else
  {
    # Breaking this into multiple comparisons for readability and clear commenting
    # If the engine IDs or boot counts don't match, this host has changed or rebooted during the scan.
    # If the time ticks decreased, then we may be seeing a replay or badly delayed packet.
    if  ( auth_engine_id != msg_auth_engine_id )
      return snmpv3_fail( reason:'engine_id' );
    else if ( auth_engine_boots != msg_auth_engine_boots )
      return snmpv3_fail( reason:'boots' );
    else if ( ( auth_engine_time - 150 > msg_auth_engine_time  ) || ( auth_engine_time + 150 < msg_auth_engine_time  ) )
      return snmpv3_fail( reason:'time' );  # RFC 3414, 3.7.a
  }

  # RFC 3414, http://www.ietf.org/rfc/rfc3414.txt, Sec 3.2: check username, check auth, then decrypt
  # however, this function does not have visibility of the encrypted data or the whole message, so we check the
  # username and return the msg_authent_params and msg_privacy_params for evaluation elsewhere.
  if ( creds[ 0 ] != msg_user_name )
    return NULL;

  ret = make_list();
  ret[ 0 ] = msg_authent_params;
  ret[ 1 ] = msg_privacy_params;
  return ret;
}


#---------------------------------------------------------#
# Function    : snmp_reply                                #
# Description : Return ber decoded snmp reply value       #
#---------------------------------------------------------#

function snmp_reply (socket, timeout, ret_err)
{
  local_var seq, res, pdu, error, oid, ret, rep, id, cmpt, vers, tmp;
  local_var msg_flags, msg_auth_priv_params, response_data_index, decrypted, whole_msg, encrypted_pdu;
  local_var total_size, variable_bindings, ret_size, ret0, ret1, i, variable, inner_seq;

  cmpt = 5;

  # should we attempt to return a non-null value if an error code
  # other than 0 is received?
  if (isnull(ret_err) || !ret_err) ret_err = FALSE;
  else ret_err = TRUE;

  while (cmpt)
  {
    rep = recv(socket:socket, length:4096, timeout:timeout);
    if (!rep)
      return NULL;
    total_size = strlen(rep);

    # First decode snmp reply (sequence)
    seq = ber_get_sequence (seq:rep);

    # seq[0] contains the number of elements in seq.
    # snmpv1/2c will have 3 parts (version, community string, body)
    # snmpv3 will have 4 parts(version, msg global data, auth data, body).
    if (isnull(seq) || ( (seq[0] != 3) && (seq[0] != 4) ))
      return NULL;

    # Check if version is equal to the SNMP version.
    vers = ber_get_int (i:seq[1]);
    if (isnull(vers) || vers != SNMP_VERSION)
      return NULL;

    # If we're dealing with SNMPv1/2c, move right on to reading the response PDU from seq[3]
    # however, for SNMPv3, the auth data is in seq[3] and the response PDU is in seq[4]
    response_data_index = 3;
    if ( vers == 3 )
    {
      # Validate header data and return relevant information
      msg_flags = snmpv3_parse_header( head_blob:seq[ 2 ] );
      if  ( ! msg_flags )
        return NULL;

      # Handle SNMPv3 Authoritative Engine Data
      msg_auth_priv_params = snmpv3_parse_authoritative( auth_blob:seq[ 3 ] );
      if  ( ! msg_auth_priv_params )
        return NULL;

      # If the packet is flagged as authenticated, check authentication.
      if  ( ord( msg_flags ) & MSG_AUTHENTICATED_FLAG )
      {
        # Replace the auth params with 12 null bytes, as if we were preparing to send.
        whole_msg = str_replace( string:rep, find:msg_auth_priv_params[ 0 ], replace:EMPTY_AUTH_STRING, count:1 );
        # Get back the response with calculated auth params.
        whole_msg = snmpv3_authenticate_incoming( auth_passwd:creds[ 1 ], whole_msg:whole_msg, alg:creds[ 2 ] );
        # Compare the packed result with the recieved data
        if  ( whole_msg != rep )
          return NULL;
        else if ( ord( msg_flags )& MSG_ENCRYPTED_FLAG )
        {
          encrypted_pdu = ber_get_octet_string( string:seq[ 4 ] );
          decrypted = snmpv3_decrypt_incoming(  msg_data:encrypted_pdu,
                                                priv_alg:creds[ 4 ],
                                                priv_param:msg_auth_priv_params[ 1 ] );
          if  ( ! decrypted )
            return NULL;
          # Replace the encrypted PDU with the decrypted one.
          seq[ 4 ] = decrypted;
        }
      }
      # Massage the returned PDU so that it can be parsed with the same process as SNMPv1/2c responses.
      response_data_index = 4;
      tmp = ber_get_sequence( seq:seq[ response_data_index ] );
      seq[ response_data_index ] = tmp[ 3 ];
    }

    # Check if Response PDU is 2
    pdu = ber_get_response_pdu( pdu:seq[ response_data_index ] );
    if (isnull(pdu) || (pdu[0] != 4))
      return NULL;

    id = ber_get_int (i:pdu[1]);
    # ID will be zero when a decryption failure occurs.  The message should still be parsed.
    if ( !isnull(id) && ( ( id == (snmp_request_id - 1) ) || id == 0 ) )
    {
      # only continue if Error == NO ERROR, unless the caller has told us to do otherwise
      error = ber_get_int (i:pdu[2]);
      if (isnull(error) || (error != 0 && !ret_err))
        return NULL;

      # Extract response
      seq = ber_get_sequence (seq:pdu[4]);
      if (isnull(seq))
        return NULL;
      variable_bindings = seq[0];
      if ((variable_bindings > 1) && (variable_bindings == (max_index(seq) - 1)))
      {
        ret_size = 0;
        ret0 = make_list();
        ret1 = make_list();
        i = -1;
        foreach variable (seq)
        {
          if (i == -1)
          {
            i++;
            continue;
          }
          inner_seq = ber_get_sequence(seq:variable);
          ret0[i] = ber_get_oid(oid:inner_seq[1]);
          ret1[i] = snmp_extract_reply(rep:inner_seq[2]);
          i++;
        }
        ret = make_list2(ret0, ret1, 0, total_size);
        return ret;
      }

      seq = ber_get_sequence (seq:seq[1]);
      if (isnull(seq) || (seq[0] != 2))
        return NULL;

      oid = ber_get_oid (oid:seq[1]);
      res = snmp_extract_reply (rep:seq[2]);                      # This appears to be reading the value incorrectly

      if ( isnull( oid ) )
        return NULL;
      else if ( oid == USM_STATS_UNKNOWN_USER_NAMES )
        return snmpv3_fail( reason:'Unknown user.' );
      else if ( oid == USM_STATS_WRONG_DIGESTS )
        return snmpv3_fail( reason:'Authentication failure.' );
      else if ( oid == USM_STATS_DECRYPTION_ERRORS )
        return snmpv3_fail( reason:'Target side  failed to decrypt of our request.' );

      ret = make_list();
      ret[0] = oid;
      ret[1] = res;
      if (ret_err) ret[2] = error;

      return ret;
    }
    cmpt--;
  }
}

####
#### snmp_put_engine_data()
#### Helper function to convert and assemble raw engine data from global values
####
function snmp_put_engine_data()
{
  local_var id, boots, entime;
  id = ber_put_octet_string( string:auth_engine_id );
  boots = ber_put_int( i:auth_engine_boots );
  entime = ber_put_int( i:auth_engine_time );
  return make_list( id, boots, entime );
}

####
#### snmp_assemble_authentication_data
#### Helper function to assemble the authoritative engine data with the rest of the authentication arguments
####
function snmp_assemble_authentication_data( auth_engine_data, msg_user_name, msg_auth_param, msg_priv_param )
{
  local_var seq;

  msg_user_name = ber_put_octet_string( string:msg_user_name );
  msg_auth_param = ber_put_octet_string( string:string( msg_auth_param ) );
  msg_priv_param = ber_put_octet_string( string:string( msg_priv_param ) );
  seq = make_list( auth_engine_data, msg_user_name, msg_auth_param, msg_priv_param );

  return ber_put_octet_string( string:ber_put_sequence( seq:seq ) );
}

####
#### snmp_assemble_request_data( seq, op )
#### Assmemble the request payload.  This *should* work for v1 and v3 payloads, but has not been tested with v1.
####
function snmp_assemble_request_data( seq, op, community, context_name, non_repeaters, max_repetitions )
{
  local_var request, request_prefix;

  if ( op == OP_GET_BULK_REQUEST )
  {
    request = ber_put_int( i:snmp_request_id )         + # Request ID
              ber_put_int( i:non_repeaters )           + # non-repeaters
              ber_put_int( i:max_repetitions )         + # max-repitions
              ber_put_sequence ( seq:make_list( seq ) ); # Object Identifier
  }
  else
  {
    request = ber_put_int( i:snmp_request_id )          + # Request Id
              ber_put_int( i:0 )                        + # Error Status: NO ERROR (0)
              ber_put_int( i:0 )                        + # Error Index (0)
              ber_put_sequence( seq:make_list( seq ) );   # Object Identifier
  }

  # Increment the request counter global.
  snmp_request_id += 1;

  # If using a community string based auth model, the first two arguments are SNMP version and the community string,
  # for USM (SNMPv3) auth the first two arguments are the context_engine_id and the context name.
  if ( SNMP_VERSION < 3 )
  {
    request_prefix =  ber_put_int( i:SNMP_VERSION ) +                       # v1 version
                      ber_put_octet_string( string:community );             # v1 community string
  }
  else if ( SNMP_VERSION == 3 )
  {
    request_prefix =  ber_put_octet_string( string:auth_engine_id ) +       # v3 contextEngineID
                      ber_put_octet_string( string:context_name );          # v3 optional contextName
  }

  if ( op == OP_GET_REQUEST  )
    request = request_prefix + ber_put_get_pdu( pdu:request );             # PDU type
  else if ( op == OP_GET_NEXT_REQUEST  )
    request = request_prefix + ber_put_get_next_pdu( pdu:request );        # PDU type
  else if ( op == OP_GET_BULK_REQUEST )
    request = request_prefix + ber_put_get_bulk_pdu( pdu:request );        # PDU type

  return ber_put_sequence( seq:make_list( request ) );
}


#---------------------------------------------------------#
# Function    : snmp_v3_initial_request                   #
# Description : Do an empty snmp v3 request to learn      #
#               remote engine information                 #
#---------------------------------------------------------#

function snmpv3_initial_request( socket, msg_global_data, timeout )
{
  if( get_kb_item( "SNMP/v3/FAILED" ) )
    return NULL;

  local_var authentication_data, snmp_header, req, rep;

  # The initial request uses null auth data
  authentication_data = snmp_assemble_authentication_data(  auth_engine_data:snmp_put_engine_data(),
                                                            msg_user_name:'',
                                                            msg_auth_param:string( 0 ),
                                                            msg_priv_param:NULL );

  snmp_header = raw_string( ber_put_int( i:SNMP_VERSION ), msg_global_data, authentication_data );

  req = snmp_assemble_request_data( seq:make_list(), op:OP_GET_REQUEST );

  rep = snmp_exchange( socket:socket, data:( ber_put_sequence( seq:make_list( snmp_header, req ) ) ), timeout:timeout );

  if ( ( isnull(rep) ) || ( rep[ 0 ] != USM_STATS_UNKNOWN_ENGINE_IDS ) )
    return snmpv3_fail( reason:'response not unknown engine id' );
  else
    {
    replace_kb_item( name:'SNMP/v3/Supported', value:1 );
    return rep[1];
    }
}

####
#### SNMPv3 Pack Global Data
#### Helper function to assembble the Global Message Data Values.
####
function snmpv3_put_msg_global_data( msg_max_size, msg_flags, msg_security_model )
{
  local_var seq;
  msg_id--;
  seq = make_list(  ber_put_int( i:msg_id ),
                    ber_put_int( i:msg_max_size ),
                    ber_put_octet_string( string:raw_string( msg_flags ) ),
                    ber_put_int( i:msg_security_model ) );
  return ber_put_sequence( seq:seq );
}

####
#### password_to_key( passwd, alg )
#### Performs key localization as per RFC 3414.
####
function password_to_key( passwd, alg )
{
  local_var buffer, inter, key;

  buffer = crap( data:passwd, length:1048576 );

  if  ( alg == 'MD5' )
    {
      inter = MD5( buffer );
      key = MD5( string( inter, auth_engine_id, inter ) );
    }
  else if( alg == 'SHA1' || alg == 'SHA' )
    {
      inter = SHA1( buffer );
      key = SHA1( string( inter, auth_engine_id, inter ) );
    }

  return key;
}

####
#### XOR
#### XOR's each byte of two bitstrings
####
function XOR( bitstring1, bitstring2 )
{
  local_var len, i, ret_value;
  ret_value = '';
  len = strlen( bitstring1 );

  if  ( len != strlen( bitstring2 ) )
    return NULL;

  for ( i = 0; i < len; i++ )
    ret_value += raw_string( ord( bitstring1[ i ] ) ^ ord( bitstring2[ i ] ) );
  return ret_value;
}

####
#### SNMPv3 usmHMACMD5AuthProtocol
#### http://www.ietf.org/rfc/rfc3414.txt
#### Section 6
function usm_HMAC_MD5_auth_protocol( auth_key, whole_msg )
{
  local_var k1, k2, result1, result2, extended_auth_key;
  extended_auth_key = string( auth_key, crap( data:raw_string( 0x00 ), length:48 ) );

  k1 = XOR( bitstring1:extended_auth_key, bitstring2:IPAD );
  k2 = XOR( bitstring1:extended_auth_key, bitstring2:OPAD );

  result1 = MD5( string( k1, whole_msg ) );
  result2 = substr( MD5( string( k2, result1 ) ), 0, 11 );

  whole_msg =  str_replace( string:whole_msg, find:EMPTY_AUTH_STRING, replace:result2, count:1 );
  return whole_msg;
}

####
#### SNMPv3 usmHMACSHAAuthProtocol
#### http://www.ietf.org/rfc/rfc3414.txt
#### Section 7
function usm_HMAC_SHA_auth_protocol( auth_key, whole_msg )
{
  local_var k1, k2, result1, result2, extended_auth_key;
  extended_auth_key = string( auth_key, crap( data:raw_string( 0x00 ), length:44 ) );

  k1 = XOR( bitstring1:extended_auth_key, bitstring2:IPAD );
  k2 = XOR( bitstring1:extended_auth_key, bitstring2:OPAD );

  result1 = SHA1( string( k1, whole_msg ) );
  result2 = substr( SHA1( string( k2, result1 ) ), 0, 11 );

  whole_msg =  str_replace( string:whole_msg, find:EMPTY_AUTH_STRING, replace:result2, count:1 );
  return whole_msg;
}

####
#### SNMPv3 USM Outgoing Message Authentication
#### http://www.ietf.org/rfc/rfc3414.txt
#### Section 3.1.8
function snmpv3_authenticate_incoming( auth_passwd, whole_msg, alg )
{
  local_var auth_key;
  alg = toupper( alg );
  auth_key = get_kb_item( 'SNMP/v3/LocalizedAuthKey' );
  if ( ! auth_key )
    return NULL;   # If we haven't stored the auth key, then this is not a response to a message we sent.
  else
    auth_key = base64_decode( str:auth_key );

  if  ( alg == 'MD5' )
    return usm_HMAC_MD5_auth_protocol( auth_key:auth_key, whole_msg:whole_msg );
  else if( alg == 'SHA1' )
    return usm_HMAC_SHA_auth_protocol( auth_key:auth_key, whole_msg:whole_msg );
  return NULL;
}


####
#### SNMPv3 USM Incoming Message Authentication
#### http://www.ietf.org/rfc/rfc3414.txt
#### Section 3.1.8
function snmpv3_authenticate_outgoing( auth_passwd, whole_msg, alg )
{
  local_var auth_key;
  alg = toupper( alg );
  auth_key = get_kb_item( 'SNMP/v3/LocalizedAuthKey' );
  if ( ! auth_key )
  {
    auth_key = password_to_key( passwd:auth_passwd, alg:alg );
    set_kb_item( name:'SNMP/v3/LocalizedAuthKey', value:base64( str:auth_key ) );
  }
  else
    auth_key = base64_decode( str:auth_key );

  if  ( alg == 'MD5' )
    return usm_HMAC_MD5_auth_protocol( auth_key:auth_key, whole_msg:whole_msg );
  else if( ( alg == 'SHA1' ) || ( alg == 'SHA' ) )
    return usm_HMAC_SHA_auth_protocol( auth_key:auth_key, whole_msg:whole_msg );
  return NULL;
}

####
#### SNMPv3 usmAESPrivProtocol
#### http://www.ietf.org/rfc/rfc3826.txt
#### Section 3.3.1
function usm_AES_priv_protocol( priv_key, msg_data )
{
  local_var aes_key;
  aes_key = substr( priv_key, 0, 15 );

  if ( ! defined_func( 'aes_cfb_encrypt' ) ) return NULL;

  local_var  salt, iv, ret, ciphertext, i, j, outblock, msg_block;

  salt = PEPP64 + mkdword( PEPPER );

  iv = mkdword( auth_engine_boots ) + mkdword( auth_engine_time ) + salt;

  if ( PEPPER < 0xffffffff )
    PEPPER += 1;
  else
    PEPPER = rand();

  # Pad out to mod 16 for AES encryption.
  while ( ( strlen( msg_data  ) % 16 ) != 0 )
    msg_data  += '\x00';

  i = 0;
  ciphertext = '';
  j = strlen( msg_data );
  while( i < j )
  {
    msg_block = substr( msg_data, i, i + 15 );
    outblock = aes_cfb_encrypt( data:msg_block, key:aes_key, iv:iv );
    iv = outblock[1];
    ciphertext += outblock[0];
    i += 16;
  }
  ret = make_list( salt, ber_put_octet_string (string:ciphertext ) );
  return ret;
}

####
#### SNMPv3 usmAESPrivProtocol
#### http://www.ietf.org/rfc/rfc3826.txt
#### Section 3.3.2
function usm_AES_priv_decrypt( priv_key, msg_data, priv_param )
{
  if ( ! defined_func( 'aes_cfb_decrypt' ) ) return NULL;

  local_var aes_key;
  aes_key = substr( priv_key, 0, 15 );

  local_var salt, iv, ret, plaintext, i, j, outblock, msg_block;
  salt = priv_param;

  if ( isnull( salt ) || ( strlen( salt  ) != 8 ) )
  return NULL;

  iv = mkdword( auth_engine_boots ) + mkdword( auth_engine_time ) + salt;

  # Pad out to mod 16 for AES encryption.
  while ( ( strlen( msg_data  ) % 16 ) != 0 )
    msg_data  += '\x00';

  i = 0;
  plaintext = '';
  j = strlen( msg_data );
  while( i < j )
  {
    msg_block = substr( msg_data, i, i + 15 );
    outblock = aes_cfb_decrypt( data:msg_block, key:aes_key, iv:iv );
    iv = outblock[1];
    plaintext += outblock[0];
    i += 16;
  }
  return plaintext;
}

####
#### SNMPv3 usmDESPrivProtocol
#### http://www.ietf.org/rfc/rfc3414.txt
#### Section 8
function usm_DES_priv_protocol( priv_key, msg_data )
{
  local_var des_key, pre_iv, salt, iv, ret, ciphertext, i, key, inter, block;

  des_key = substr( priv_key, 0, 7 );
  pre_iv  = substr( priv_key, 8, 15 );

  salt = mkdword( auth_engine_boots ) + mkdword( PEPPER );
  if ( PEPPER < 0xffffffff )
    PEPPER += 1;
  else
    PEPPER = rand();

  iv = XOR( bitstring1:salt, bitstring2:pre_iv );

  # Pad out to mod 8 = 0 for DES encryption.
  while ( ( strlen( msg_data  ) % 8 ) != 0 )
    msg_data  += '\x00';

  i = 0;
  ciphertext = '';
  key = iv;
  while( i < strlen( msg_data ) )
  {
    block = substr( msg_data, i, i + 7 );
    block = XOR( bitstring1:key, bitstring2:block );
    inter = DES( in:block, key:set_des_key(key:des_key), _string:FALSE, type:1 );         # TYPE 1 = encrypt
    ciphertext += inter;
    key = inter;
    i += 8;
  }
  ret = make_list( salt,  ber_put_octet_string (string:ciphertext ) );
  return ret;
}

####
#### SNMPv3 usmDESPrivProtocol
#### http://www.ietf.org/rfc/rfc3414.txt
#### Section 8.2.4.2
function usm_DES_priv_decrypt( priv_key, msg_data, priv_param )
{
  local_var des_key, pre_iv, iv, ret, plaintext, i, key, plainblock, inter, block;

  des_key = substr( priv_key, 0, 7 );
  pre_iv  = substr( priv_key, 8, 15 );

  iv = XOR( bitstring1:priv_param, bitstring2:pre_iv );

  if ( ( strlen( msg_data  ) % 8 ) != 0 )
    return NULL;

  i = 0;
  plaintext = '';
  key = iv;
  while( i < strlen( msg_data ) )
  {
    block = substr( msg_data, i, i + 7 );
    inter = DES( in:block, key:set_des_key(key:des_key), _string:FALSE, type:0 );           # TYPE 0 = decrypt
    plainblock = XOR( bitstring1:key, bitstring2:inter );
    plaintext += plainblock ;
    key = block;
    i += 8;
  }
  return plaintext;
}

####
#### SNMPv3 USM Message Encryption
#### http://www.ietf.org/rfc/rfc3414.txt
#### Section 3.1.8
function snmpv3_encrypt_outgoing( priv_passwd, msg_data, auth_alg, priv_alg )
{
  local_var priv_key;
  auth_alg = toupper( auth_alg);
  priv_alg = toupper( priv_alg);

  priv_key = get_kb_item( 'SNMP/v3/LocalizedPrivKey' );
  if ( ! priv_key )
  {
    priv_key = password_to_key( passwd:priv_passwd, alg:auth_alg );
    set_kb_item( name:'SNMP/v3/LocalizedPrivKey', value:base64( str:priv_key ) );
  }
  else
    priv_key = base64_decode( str:priv_key );

  if  ( priv_alg == 'DES' )
    return usm_DES_priv_protocol( priv_key:priv_key, msg_data:msg_data );
  else if ( priv_alg == 'AES' )
    return usm_AES_priv_protocol( priv_key:priv_key, msg_data:msg_data );
  return NULL;
}

####
#### SNMPv3 USM Message Decryption
#### http://www.ietf.org/rfc/rfc3414.txt
#### Section 3.2.8
function snmpv3_decrypt_incoming( msg_data, priv_alg, priv_param  )
{
  local_var priv_key;
  priv_alg = toupper( priv_alg);

  priv_key = get_kb_item( 'SNMP/v3/LocalizedPrivKey' );
  if ( ! priv_key )
    return NULL;   # If we haven't stored the priv_key  then this is not a response to a message we sent.
  else
    priv_key  = base64_decode( str:priv_key  );

  if  ( priv_alg == 'DES' )
    return usm_DES_priv_decrypt( priv_key:priv_key, msg_data:msg_data, priv_param:priv_param);
  else if ( priv_alg == 'AES' )
    return usm_AES_priv_decrypt( priv_key:priv_key, msg_data:msg_data, priv_param:priv_param );
  return NULL;
}



####
####
#### GENERIC SNMPv3 REQUEST
####
function snmpv3_request( socket, community, oid, timeout, op, ret_err, non_repeaters, max_repetitions )
{
  local_var seq, req, res, msg_flags, msg_global_data, snmp_header, whole_msg, snmpv3_connected;
  local_var salt, authentication_data;

  if ( isnull(op) ) op = OP_GET_REQUEST;
  # Message Global Data Values
  if ( ! msg_id )
    msg_id = rand();
  msg_flags = raw_string( MSG_REPORTABLE_FLAG );                    # Set the reportable flag.

  # If we are missing any authoritative engine data then we must be making an initial connection attempt
  if( ( ! auth_engine_id ) || ( ! auth_engine_boots  ) || ( !  auth_engine_time  ) )
  {
    msg_global_data = snmpv3_put_msg_global_data( msg_max_size:MSG_MAX_SIZE,
                                                  msg_flags:msg_flags,
                                                  msg_security_model:USM_SECURITY_MODEL );
    snmpv3_connected = snmpv3_initial_request( socket:socket, msg_global_data:msg_global_data, timeout:timeout);
    if(get_kb_item("SNMP/v3/FAILED"))
      return NULL;
  }

  # creds is global so that it can be used in the return auth and decoding.
  creds = split( base64_decode( str:substr( community, 1 ) ), sep:';', keep:FALSE );

  # Confirm that creds has split out properly
  if ( ( ! creds ) || ( max_index( creds ) != 6 ) )
    return NULL;

  # Bit bash the security level with the reportable flag.
  msg_flags = ord( msg_flags ) | creds[ 5 ];
  msg_global_data = snmpv3_put_msg_global_data( msg_max_size:MSG_MAX_SIZE,
                                                msg_flags:msg_flags,
                                                msg_security_model:USM_SECURITY_MODEL  );

  # Assemble the OID sequence
  seq = ber_put_sequence( seq:make_list( ber_put_oid( oid:oid ), ber_put_null() ) );

  # Assemble msg data
  req = snmp_assemble_request_data( seq:seq, op:op, non_repeaters:non_repeaters, max_repetitions:max_repetitions);
  salt = NULL;

  if ( creds[ 5 ] == USM_LEVEL_AUTH_PRIV )
  {
    req = snmpv3_encrypt_outgoing( priv_passwd:creds[ 3 ], msg_data:req, auth_alg:creds[ 2 ], priv_alg:creds[ 4 ] );
    salt = req[ 0 ];
    req = req[ 1 ];
  }

  authentication_data = snmp_assemble_authentication_data(  auth_engine_data:snmp_put_engine_data(),
                                                            msg_user_name:creds[ 0 ],
                                                            msg_auth_param:string( EMPTY_AUTH_STRING ),
                                                            msg_priv_param:salt );

  # Assmble the snmp message header
  snmp_header = string( ber_put_int( i:SNMP_VERSION ), msg_global_data, authentication_data );

  # Assemble the whole message
  whole_msg = ber_put_sequence( seq:make_list( snmp_header, req ) );

  # Sign the message for authentication if required
  if (creds[2] != "")
    whole_msg = snmpv3_authenticate_outgoing( auth_passwd:creds[ 1 ], whole_msg:whole_msg, alg:creds[ 2 ] );

  # Send and get the result
  res = snmp_exchange( socket:socket, data:whole_msg, timeout:timeout, ret_err:ret_err);

  return res;
}

#---------------------------------------------------------#
# Function    : snmp_get_bulk_request                     #
# Description : Do an snmp get bulk request and reply     #
# Return      : An array containing two parallel arrays   #
#               of OIDs and values                        #
#---------------------------------------------------------#

function snmp_get_bulk_request( socket, community, oid, timeout, non_repeaters, max_repetitions )
{
  local_var seq, req, res;

  if ( isnull(non_repeaters) )
    non_repeaters = 0;

  if ( isnull(max_repetitions) )
    max_repetitions = 10;

  if  ( isnull( timeout ) )
    timeout = 2;

  if ( ( community[ 0 ] == ';' ) && ( SNMP_VERSION == 0x03 ) )
   {
      res = snmpv3_request(
        socket:socket,
        community:community,
        oid:oid,
        timeout:timeout,
        op:OP_GET_BULK_REQUEST,
        non_repeaters:non_repeaters,
        max_repetitions:max_repetitions
      );
      return res;
   }
  else
  {
    seq = make_list(
                    ber_put_oid (oid:oid),
                    ber_put_null ()
                   );

    seq = make_list( ber_put_sequence(seq:seq) );

    req =  ber_put_int (i:snmp_request_id)          + # Request Id
           ber_put_int (i:non_repeaters)            + # non-repeaters
           ber_put_int (i:max_repetitions)          + # max_repeaters
           ber_put_sequence (seq:seq);                # Object Identifier
    req =  ber_put_int (i:SNMP_VERSION)             + # version
           ber_put_octet_string (string:community)  + # community string
           ber_put_get_bulk_pdu (pdu:req);            # PDU type

    req =  ber_put_sequence (seq:make_list(req));

    snmp_request_id += 1;

    send (socket:socket, data:req);
    res = snmp_reply (socket:socket, timeout:timeout);

    return res;
  }
}

#---------------------------------------------------------#
# Function    : snmp_request                              #
# Description : Do an snmp request and return reply       #
#---------------------------------------------------------#

function snmp_request( socket, community, oid, timeout )
{
  local_var seq, req, res;

  if  ( isnull( timeout ) )
    timeout = 2;

  if ( ( community[ 0 ] == ';' ) && ( SNMP_VERSION == 0x03 ) )
   {
      res = snmpv3_request( socket:socket, community:community, oid:oid, timeout:timeout, op:OP_GET_REQUEST );
      if ( isnull(res) ) return NULL;
      else return res[1];
   }
  else
  {
    seq = make_list(
                    ber_put_oid (oid:oid),
                    ber_put_null ()
                   );

    seq = make_list( ber_put_sequence(seq:seq) );

    req =  ber_put_int (i:snmp_request_id)          + # Request Id
           ber_put_int (i:0)                        + # Error Status: NO ERROR (0)
           ber_put_int (i:0)                        + # Error Index (0)
           ber_put_sequence (seq:seq);                # Object Identifier

    req =  ber_put_int (i:SNMP_VERSION)             + # version
           ber_put_octet_string (string:community)  + # community string
           ber_put_get_pdu (pdu:req);                 # PDU type

    req =  ber_put_sequence (seq:make_list(req));

    snmp_request_id += 1;

    send (socket:socket, data:req);
    res = snmp_reply (socket:socket, timeout:timeout);

    if ( isnull( res ) )
      return NULL;
    else
      return res[1];
  }
}


#---------------------------------------------------------#
# Function    : snmp_request_next                         #
# Description : Do an snmp request_next and return reply  #
#---------------------------------------------------------#

function snmp_request_next (socket, community, oid, timeout, ret_err)
{
 local_var seq, req, res;

 if ( ( community[ 0 ] == ';' ) && ( SNMP_VERSION == 0x03 ) )
    return snmpv3_request( socket:socket, community:community, oid:oid, timeout:timeout, op:OP_GET_NEXT_REQUEST, ret_err:ret_err );
 else
 {
    seq = make_list(
                   ber_put_oid (oid:oid),
                   ber_put_null ()
                  );

    seq = make_list( ber_put_sequence(seq:seq) );

    req = ber_put_int (i:snmp_request_id)          + # Request Id
          ber_put_int (i:0)                        + # Error Status: NO ERROR (0)
          ber_put_int (i:0)                        + # Error Index (0)
          ber_put_sequence (seq:seq);                # Object Identifier

    req = ber_put_int (i:SNMP_VERSION)             + # version
          ber_put_octet_string (string:community)  + # community string
          ber_put_get_next_pdu (pdu:req);            # PDU type

    req = ber_put_sequence (seq:make_list(req));
 }

 snmp_request_id += 1;

 send (socket:socket, data:req);

 res = snmp_reply (socket:socket, timeout:timeout, ret_err:ret_err);

 if (end_mib)
   return NULL;

 return res;
}

#---------------------------------------------------------#
# Function      : snmp_request_set                        #
# Description   : Do an snmp request_set and return reply #
# Required args : socket, community, oid, type, value     #
#                                                         #
# Currently not implemented for v3                        #
#---------------------------------------------------------#

function snmp_request_set (socket, community, oid, type, value, timeout, ret_err)
{
 local_var seq, req, res;

 if ( ( community[ 0 ] == ';' ) && ( SNMP_VERSION == 0x03 ) )
 {
    #return snmpv3_request( socket:socket, community:community, oid:oid, timeout:timeout, op:OP_SET_REQUEST, ret_err:ret_err );
    # not implemented yet
    return NULL;
 }
 else
 {
    seq = make_list(ber_put_oid (oid:oid));

    if (type == TYPE_INTEGER)
      seq = make_list(seq, ber_put_int(i:value));
    else if (type == TYPE_OCTET_STRING)
      seq = make_list(seq, ber_put_octet_string(string:value));
    else if (type == TYPE_NULL)
      seq = make_list(seq, ber_put_null());
    else
    {
      #err_print('snmp_request_set(): unsupported type "' + type + '"');
      return NULL;
    }

    seq = make_list( ber_put_sequence(seq:seq) );

    req = ber_put_int (i:snmp_request_id)          + # Request Id
          ber_put_int (i:0)                        + # Error Status: NO ERROR (0)
          ber_put_int (i:0)                        + # Error Index (0)
          ber_put_sequence (seq:seq);                # Object Identifier

    req = ber_put_int (i:SNMP_VERSION)             + # version
          ber_put_octet_string (string:community)  + # community string
          ber_put_set_pdu (pdu:req);                 # PDU type

    req = ber_put_sequence (seq:make_list(req));
 }

 snmp_request_id += 1;

 send (socket:socket, data:req);

 res = snmp_reply (socket:socket, timeout:timeout, ret_err:ret_err);

 if (end_mib)
   return NULL;

 return res;
}


#---------------------------------------------------------#
# Function    : scan_snmp_string                          #
# Description : do a snmp string scan with get_next_pdu   #
#---------------------------------------------------------#

function scan_snmp_string(socket, community, oid)
{
 local_var soid, list, port;

 list = NULL;
 soid = oid;

 while(1)
 {
  port = snmp_request_next (socket:socket, community:community, oid:soid);
  if (!isnull(port) && egrep (pattern:string("^",str_replace(string:oid, find:".", replace:'\\.'),"\\."), string:port[0]))
  {
   if ( strlen(port[1] ) ) list = string (list, port[1], "\n");
   soid = port[0];
  }
  else
    break;
 }

 return list;
}


#---------------------------------------------------------#
# Function    : is_valid_snmp_product                     #
# Description : checks if the product oid is from the same#
#               manufacturer                              #
#---------------------------------------------------------#

function is_valid_snmp_product(manufacturer, oid)
{
 if (egrep(pattern:string("^",manufacturer,"\\..*"), string:oid))
   return TRUE;

 return FALSE;
}

#---------------------------------------------------------#
# Function    : issameoid                                 #
# Description : check if oid is in the item than oid      #
#---------------------------------------------------------#

function issameoid(origoid, oid)
{
 local_var tmp;

 if (strlen(oid) < strlen(origoid))
   return FALSE;

 tmp = substr(oid,0,strlen(origoid));

 if ( tmp != string(origoid,"."))
   return FALSE;

 return TRUE;
}


####
#### Set SNMP_VERSION value
####
####
function set_snmp_version( version )
{
  if  ( SNMP_VERSION != version )
  {
    _SNMP_VERSION = SNMP_VERSION;
    SNMP_VERSION = version;
    return TRUE;
  }
  return NULL;
}

####
#### RESET SNMP_VERSION value
####
####
function reset_snmp_version()
{
  if  ( SNMP_VERSION != _SNMP_VERSION )
  {
    SNMP_VERSION = _SNMP_VERSION;
    return TRUE;
  }
  return NULL;
}
