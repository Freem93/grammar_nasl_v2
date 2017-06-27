#TRUSTED 8fb0b1f2d9dad4991a7b6ed4c1783428c8782703e6ab4b3031adac2e07ff07ecdbb8cbfa90e3f8ea0542df400dec92914688eefab1c0a91c3754f179f7b4f2efea1086e7526f172a631c73d6abb4337f57ef1b573cb2b136b921ec703b904761eae51d88e0f7eebcca5f1a1e346254fd806c91a55dfa3dd8664dffc749c3163033166f4f431786f8887e01475833d84e166fb8f09478bcad7f2783f278d7c2e10b80b20c8b6cfa4f9821a61681a9e2199fe42892bbbb568c33168700f8b6415c50b19a0f59585007b52ba9b33b5c1d21bde757031ae42968a8c6f20477e57a638631461111ae7e554a99b42f83dacd462bb3de0aa381ae42f1acfb0d8a61d7121d1be35684d3f067021788cebb05bbb8c0ccb667ab397c2bb838186e698cd2698987161cee335b23ea9247020214ffe06cf58b0ab7a79b233418c3b2165c8d209f063c09eaff1c9ddad7724acfb2c2374f6b4327a808df6b49d86487fd760efb90eb37d0a5d28a9dfa0dd3a773304b6269b0d37415aa4b89ca473ca5224771616468a92099a158a9356fb4b0b8a7553d6110f7bc9f3a74f97575611cef639b2b11ea6137b2d8f3bb534c14dd2db1701d89f14105b92af35ca4d62065eaa0aa3cc62aa83f3ab8717404de63da68c377b4769204d704b4614a928fd8d5a1c45a0b740d9fc1f00791cfef0a363d8e8d7f29a1334d3aa168589e1e018b9ee444a0ba
# -*- Fundamental -*-
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
# Revision 1.33

include('crypto_func.inc');




#---------------------------------------------------------#
# Function    : raw_byte                                  #
# Description : Convert a byte to raw data                #
#---------------------------------------------------------#

function raw_byte (b)
{
 return raw_string (b);
}


#---------------------------------------------------------#
# Function    : raw_word                                  #
# Description : Convert a word to raw data                #
#---------------------------------------------------------#

function raw_word (w)
{
 return raw_string ( (w)     & 255,
                     (w>>8)  & 255 );
}


#---------------------------------------------------------#
# Function    : raw_dword                                 #
# Description : Convert a dword to raw data               #
#---------------------------------------------------------#

function raw_dword (d, be)
{
 if(isnull(be) || be == FALSE)
 {
  return raw_string ( (d)    & 255,
                     (d>>8)  & 255,
                     (d>>16) & 255,
                     (d>>24) & 255 );
 }                   
  return raw_string ((d>>24) & 255,
                     (d>>16) & 255,
                     (d>>8)  & 255,
                     (d)     & 255);
}


#---------------------------------------------------------#
# Function    : get_byte                                  #
# Description : Extract a byte from a blob                #
#---------------------------------------------------------#

function get_byte (blob,pos)
{
 if (pos > (strlen (blob) - 1))
   return NULL;

 return ( ord(blob[pos]) );
}


#---------------------------------------------------------#
# Function    : get_word                                  #
# Description : Extract a word from a blob                #
#---------------------------------------------------------#

function get_word (blob,pos)
{
 if (pos > (strlen (blob) - 2))
   return NULL;

 return ( ord(blob[pos]) + (ord(blob[pos+1]) << 8) );
}


#---------------------------------------------------------#
# Function    : get_dword                                 #
# Description : Extract a dword from a blob               #
#---------------------------------------------------------#

function get_dword (blob, pos)
{
 if (pos > (strlen (blob) - 4))
   return NULL;

 return ( ord(blob[pos]) + 
          (ord(blob[pos+1]) << 8) +
          (ord(blob[pos+2]) << 16) +
          (ord(blob[pos+3]) << 24) );
}


#---------------------------------------------------------#
# Function    : get_checksum_type                         #
# Description : return checksum type                      #
#---------------------------------------------------------#

function get_checksum_type (enc_type)
{
 if (enc_type == 23)
   return -138;
 if (enc_type == 3)
   return 8;
 if (enc_type == 18)
   return 16;
 if (enc_type == 17)
   return 15;
 return 0;
}


#---------------------------------------------------------#
# Function    : supported_encryption_type                 #
# Description : check if encryption type is supported     #
#---------------------------------------------------------#

function supported_encryption_type (type)
{
 if ((type != 23) && # arcfour
     (type != 3)  && # des-cbc-md5
     (type != 18) && # aes256
     (type != 17))   # aes128 
   return FALSE;
 
 return TRUE;
}


#---------------------------------------------------------#
# Function    : kerberos_checksum                         #
# Description : checksum data                             #
#---------------------------------------------------------#
function kerberos_checksum (key, type, data, enc_type)
{
 local_var enckey, keysize;
 if (enc_type == 23)
   return rc4_hmac_checksum (key:key, type:raw_dword(d:type), data:data, real_key:TRUE);
 if (enc_type == 3)
 {
  return des_cbc_md5_checksum (data:data, key:key);
 }
 if(enc_type == 18 || enc_type == 17)
 {
  return krb_aes_checksum(data:data, key:key, keyusage: raw_dword(d:type, be:TRUE));
 }
 return NULL;
}



#---------------------------------------------------------#
# Function    : kerberos_decrypt                          #
# Description : decrypt data                              #
#---------------------------------------------------------#
function kerberos_decrypt (key, type, data, enc_type)
{
 local_var enckey, keysize;

 if (enc_type == 23)
   return rc4_hmac_decrypt (key:key, type:raw_dword(d:type), data:data, real_key: TRUE);
 if (enc_type == 3)
 {
  return des_cbc_md5_decrypt (data:data, key:key);
 }
 if(enc_type == 18 || enc_type == 17)
 {
  return krb_aes_decrypt(data:data, key:key, keyusage: raw_dword(d:type, be: TRUE));
 }

  return NULL;
}

#---------------------------------------------------------#
# Function    : kerberos_encrypt                          #
# Description : encrypt data                              #
#---------------------------------------------------------#
function kerberos_encrypt (key, type, data, enc_type)
{
 local_var enckey, keysize;

 if (enc_type == 23)
   return rc4_hmac_encrypt (key:key, type:raw_dword(d:type), data:data, real_key:TRUE);
 if (enc_type == 3)
 {
  return des_cbc_md5_encrypt (data:data, key:key);
 }
 if(enc_type == 18 || enc_type == 17)
 {
  return krb_aes_encrypt(data:data, key:key, keyusage: raw_dword(d:type, be: TRUE));
 }

 return NULL;
}

#---------------------------------------------------------#
# Function    : der_length                                #
# Description : return raw der length of data             #
#---------------------------------------------------------#

function der_length (data)
{
 local_var tmp, length, len;

 length = NULL;
 len = strlen (data);

 while (len != 0)
 {
  length = raw_string (len % 256) + length;
  len = len / 256;
 }
 
 if ((strlen (length) > 1) || ((strlen(length) == 1) && (ord(length[0]) > 127)))
   length = raw_string (128 + strlen (length)) + length;

 if (isnull(length)) length = raw_string(0);

 return length;
}


#---------------------------------------------------------#
# Function    : der_encode                                #
# Description : Return der encoded data                   #
#---------------------------------------------------------#

function der_encode (tag,data)
{
 if (isnull (data))
   return NULL;

 return raw_string (tag) + der_length(data:data) + data;
}


function integer (i)
{
 local_var j,k;

 j = 0;

 for (k=0; k < strlen(i); k++)
 {
  j = j * 256 + ord(i[k]);
 }
 
 return j;
}


#---------------------------------------------------------#
# Function    : der_decode                                #
# Description : Return der decoded data                   #
#               [0] = code                                #
#               [1] = data                                #
#               [2] = next pos in buffer                  #
#---------------------------------------------------------#

function der_decode (data, pos, sloppy)
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

  len2 = integer (i:substr (data, j, j + len - 1));
  j += len;
  len = len2;
 }
 
 if (strlen(data) - j < len)
 {
   # Permit sloppy parsing, where if we're missing part of the body we
   # return what we do have.
   if (!sloppy)
     return NULL;
   len = strlen(data) - j;
 }

 tmp[1] = substr(data,j,j+len-1);
 tmp[2] = j + len;

 return tmp;
}


#---------------------------------------------------------#
# Function    : der_encode_oid                            #
# Description : Return der encoded OID (string)           #
#               ex: "1.2.840.113554.1.2.2"                #
#---------------------------------------------------------#

function der_encode_oid (oid)
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
 return der_encode (tag:0x06, data:encoded);
}


#---------------------------------------------------------#
# Function    : der_decode_oid                            #
# Description : Return OID (string)                       #
#               ex: "1.2.840.113554.1.2.2"                #
#---------------------------------------------------------#

function der_decode_oid (oid)
{
 local_var soid, i, val;

 if (strlen (oid) < 1)
   return NULL;

 soid = string (ord (oid[0]) / 40, ".", ord (oid[0]) % 40);

 for (i = 1; i < strlen(oid); i++)
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
# Function    : der_encode_int                            #
# Description : Return der encoded INTEGER                #
#---------------------------------------------------------#

function der_encode_int (i)
{
 local_var val,j,tmp;

 if (isnull (i))
   return NULL;

 val[0] = i & 255;
 val[1] = (i>>8)  & 255;
# val[2] = (i>>16) & 255;
# val[3] = (i>>24) & 255;

 j = 3;
 while ((val[j] == 0) && (j != 0))
   j--;

 tmp = NULL;
 while (j != 0)
 {
  tmp += raw_string (val[j]);
  j--;
 }

 tmp += raw_string (val[j]);
 
 return der_encode (tag:0x02, data:tmp);
}


#---------------------------------------------------------#
# Function    : der_encode_int32                          #
# Description : Return der encoded INTEGER                #
#---------------------------------------------------------#

function der_encode_int32 (i)
{
 local_var tmp;

 if (isnull (i))
   return NULL;

 tmp = raw_string ((i>>24) & 255,
                   (i>>16) & 255,
                   (i>>8)  & 255,
                   i & 255);

 return der_encode (tag:0x02, data:tmp);
}


#---------------------------------------------------------#
# Function    : der_encode_string                         #
# Description : Return der encoded STRING                 #
#---------------------------------------------------------#

function der_encode_string (string)
{
 if (isnull (string))
   return NULL;
   
 return der_encode (tag:0x1B, data:string);
}


#---------------------------------------------------------#
# Function    : der_encode_sequence                       #
# Description : Return der encoded SEQUENCE               #
#---------------------------------------------------------#


function der_encode_sequence (seq)
{
 local_var encoded, max, i, j, val;

 if (isnull (seq))
   return NULL;
   
 max = max_index (seq);
 if (max == 0)
   return NULL;

 i = 0xA0;
 
 encoded = NULL;
 
 for (j=0; j < max; j++)
 {
  val = seq[j];
  if (!isnull(val))
  {
    encoded += der_encode (tag:i, data:val);
  }
  i++;
 }

 # SEQUENCE Tag = 0x30
 return der_encode (tag:0x30, data:encoded); 
}


#---------------------------------------------------------#
# Function    : der_encode_name                           #
# Description : Return type/name                          #
#---------------------------------------------------------#
#                                                         #
# PrincipalName ::= SEQUENCE {                            #
#   name-type[0]     INTEGER,                             #
#   name-string[1]   SEQUENCE OF GeneralString            #
# }                                                       #
#                                                         #
#---------------------------------------------------------#

function der_encode_name (type, name1, name2)
{
 local_var list, names;

 if (isnull (name1) && isnull (name2))
   return NULL;
   
 list = NULL;
 
 names = der_encode_string (string:name1);
 names += der_encode_string (string:name2);
 
 list[0] = der_encode_int (i:type);
 list[1] = der_encode_list (list:names);

 return der_encode_sequence (seq:list); 
}


#---------------------------------------------------------#
# Function    : der_encode_time                           #
# Description : Return der encoded KerberosTime           #
#---------------------------------------------------------#

function der_encode_time (time)
{
 if (isnull (time))
   return NULL;
   
 return der_encode (tag:0x18, data:time);
}


#---------------------------------------------------------#
# Function    : der_parse_data                            #
# Description : Return der decoded data                   #
#---------------------------------------------------------#

function der_parse_data (tag,data)
{
 local_var tmp;

 tmp = der_decode (data:data);
 if (isnull (tmp) || (tmp[0] != tag))
   return NULL;

 return tmp[1];
}


#---------------------------------------------------------#
# Function    : der_parse_list                            #
# Description : Return der decoded list                   #
#---------------------------------------------------------#

function der_parse_list (list)
{
 local_var tmp,pos,i,ret;

 if (!list)
   return NULL;
 
 tmp = NULL;
 tmp[0] = 0;
 
 pos = 0;
 i = 1;
 while (pos < strlen(list))
 {
  ret = der_decode (data:list,pos:pos);
  if (isnull(ret))
    return NULL;

  tmp[i] = substr (list, pos, ret[2]-1);
  tmp[0] = tmp[0] + 1;
  pos = ret[2];
  i++;
 }

 return tmp;
}


#---------------------------------------------------------#
# Function    : der_parse_sequence                        #
# Description : Return der decoded sequence               #
#---------------------------------------------------------#

function der_parse_sequence (seq,num,list)
{
 local_var tmp, dseq, val, i, pos, ret;
 
 dseq = der_decode (data:seq);
 if (isnull(dseq) || (dseq[0] != 0x30))
   return NULL;

 if (!isnull(list) && (list == TRUE))
   return der_parse_list (list:dseq[1]);
 
 tmp = NULL;
 for (i=0; i < num; i++)
   tmp[i] = NULL;
 
 pos = i = 0;
 while (pos < strlen(dseq[1]))
 {
  ret = der_decode (data:dseq[1],pos:pos);
  if (isnull(ret))
    return NULL;
  
  val = ret[0] - 0xA0;
  if (val < 0)
    return NULL;
  
  tmp[val] = ret [1];
  pos = ret[2];
 }
 
 return tmp;
}


#---------------------------------------------------------#
# Function    : der_parse_int                             #
# Description : Return der decoded integer                #
#---------------------------------------------------------#

function der_parse_int (i)
{
 local_var tmp;

 tmp = der_parse_data (tag:0x02, data:i);
 if (!tmp)
   return NULL;

 tmp = integer (i:tmp);
 if (isnull(tmp))
   return NULL;

 return tmp;
}


#---------------------------------------------------------#
# Function    : der_parse_bool                            #
# Description : Return der decoded boolean                #
#---------------------------------------------------------#

function der_parse_bool (bool)
{
 local_var tmp;

 tmp = der_parse_data (tag:0x01, data:bool);
 if (!tmp)
   return NULL;

 tmp = integer(i:tmp);
 if (isnull(tmp))
   return NULL;

 if (tmp == 0)
   tmp = FALSE;
 else
   tmp = TRUE;

 return tmp;
}


#---------------------------------------------------------#
# Function    : der_parse_octet_string                    #
# Description : Return der decoded octet string           #
#---------------------------------------------------------#

function der_parse_octet_string (string)
{
 return der_parse_data (tag:0x04, data:string);
}


#---------------------------------------------------------#
# Function    : der_parse_oid                             #
# Description : Return der decoded oid                    #
#---------------------------------------------------------#

function der_parse_oid (oid)
{
 local_var tmp;

 tmp = der_parse_data (tag:0x06, data:oid);
 if (!tmp)
   return NULL;

 tmp = der_decode_oid (oid:tmp);
 if (!tmp)
   return NULL;

 return tmp;
}


#---------------------------------------------------------#
# Function    : der_parse_list_oid                        #
# Description : Return der decoded oid list               #
#               "oid1 oid2 ..."                           #
#---------------------------------------------------------#

function der_parse_list_oid (list)
{
 local_var tmp, seq, i;

 tmp = NULL;

 seq = der_parse_sequence (seq:list,list:TRUE);
 if (isnull(seq))
   return NULL;
 
 for (i=0;i < seq[0];i++)
 {
  tmp += der_parse_oid (oid:seq[i+1]) + " ";
 }

 return tmp;
}


#---------------------------------------------------------#
# Function    : der_encode_paenc                          #
# Description : Return der encoded PA-ENC                 #
#---------------------------------------------------------#
#                                                         #
# PA-ENC-TS-ENC ::= SEQUENCE {                            #
#   patimestamp [0] KerberosTime, -- client's time        #
#   pausec      [1] INTEGER OPTIONAL                      #
# }                                                       #
#                                                         #
#---------------------------------------------------------#

function der_encode_paenc(time)
{
 local_var paenc;

 paenc = NULL;
 paenc[0] = der_encode_time (time:time);
 paenc[1] = NULL;

 return der_encode_sequence (seq:paenc);
}


#---------------------------------------------------------#
# Function    : der_encode_octet_string                   #
# Description : Return der encoded OCTET STRING           #
#---------------------------------------------------------#

function der_encode_octet_string (string)
{
 return der_encode (tag:0x04, data:string);
}


#---------------------------------------------------------#
# Function    : der_encode_padata                         #
# Description : Return der encoded PA-DATA                #
#---------------------------------------------------------#
#                                                         #
# PA-DATA ::= SEQUENCE {                                  #
#   padata-type  [1] INTEGER,                             #
#   padata-value [2] OCTET STRING,                        #
# }                                                       #
#                                                         #
#---------------------------------------------------------#

function der_encode_padata (type,value)
{
 local_var pa_data;

 pa_data = NULL;

 pa_data[0] = NULL;
 #pa_data[1] = der_encode_int (i:type);
 pa_data[1] = der_encode_int32 (i:type);
 pa_data[2] = der_encode_octet_string (string:value);

 return der_encode_sequence (seq:pa_data);
}


#---------------------------------------------------------#
# Function    : der_encode_crypt                          #
# Description : Return der encoded/crypted structure      #
#---------------------------------------------------------#
function der_encode_crypt (data, key, type, enc_type)
{
 local_var crypted, encrypted_data;

 encrypted_data = kerberos_encrypt (key:key, type:type, data:data, enc_type:enc_type);

 crypted = NULL;
 crypted[0] = der_encode_int (i:enc_type);
 crypted[1] = NULL;
 crypted[2] = der_encode_octet_string (string:encrypted_data);

 return der_encode_sequence (seq:crypted);
}

#---------------------------------------------------------#
# Function    : der_encode_list                           #
# Description : Return der encoded list                   #
#---------------------------------------------------------#

function der_encode_list (list)
{
 return der_encode (tag:0x30, data:list);
}


#---------------------------------------------------------#
# Function    : der_encode_kdcreq                         #
# Description : Return der encoded KDC-REQ                #
#---------------------------------------------------------#
#                                                         #
# KDC-REQ ::= SEQUENCE {                                  #
#   pvno     [1] INTEGER,                                 #
#   msg-type [2] INTEGER,                                 #
#   padata   [3] SEQUENCE OF PA-DATA OPTIONAL,            #
#   req-body [4] KDC-REQ-BODY                             #
# }                                                       #
#                                                         #
#---------------------------------------------------------#

function der_encode_kdcreq (pvno, msg_type, list, req_body)
{
 local_var l;

 l = NULL;

 l[0] = NULL;
 l[1] = der_encode_int (i:pvno);
 l[2] = der_encode_int (i:msg_type);
 l[3] = der_encode_list (list:list);
 l[4] = req_body;

 return der_encode_sequence (seq:l);
}


function der_encode_request (req)
{
 local_var request;
 
 request = NULL;
 request[0] = der_encode (tag:0x01, data:req); 
 
 return der_encode_sequence(seq:request);
}



#---------------------------------------------------------#
# Function    : der_encode_kdc_req_body                   #
# Description : Return der encoded KDC-REQ-BODY           #
#---------------------------------------------------------#
#                                                         #
# KDC-REQ-BODY ::= SEQUENCE {                             #
#   kdc-options [0] KDCOptions,                           #
#   cname       [1] PrincipalName OPTIONAL,               #
#   realm       [2] Realm, -- Server's realm              #
#   sname       [3] PrincipalName OPTIONAL,               #
#   from        [4] KerberosTime OPTIONAL,                #
#   till        [5] KerberosTime,                         #
#   rtime       [6] KerberosTime OPTIONAL,                #
#   nonce       [7] INTEGER,                              #
#   etype       [8] SEQUENCE OF INTEGER, -- EncType       #
#   addresses   [9] HostAddresses OPTIONAL,               #
#   enc-authorization-data [10]  EncryptedData OPTIONAL,  #
#   additional-tickets     [11]  SEQUENCE OF Ticket OPT   #
# }                                                       #
#                                                         #
#---------------------------------------------------------#

function der_encode_kdc_req_body (principal,realm,service,hosts)
{
 local_var list, options;

 list = options = NULL;

 options = der_encode (tag:0x03, data:raw_string (0x00,0x00,0x00,0x00,0x00));
 
 list[0] = options;
 if (!isnull(principal))
   list[1] = der_encode_name (type:1, name1:principal, name2:NULL);
 else
   list[1] = NULL;
 list[2] = der_encode_string (string:realm);
 list[3] = service;
 list[4] = NULL;
 list[5] = der_encode_time (time:"20370913024805Z");
 list[6] = der_encode_time (time:"20370913024805Z");
 list[7] = der_encode_int (i:rand());
 # 23 = rc4-hmac-md5, 18 = aes256-cts-hmac-sha1-96, 17 = aes128-cts-hmac-sha1--96, 3 = des-cbc-md5
 list[8] = der_encode_list (list:der_encode_int(i:18)+ der_encode_int(i:17) + der_encode_int(i:23));
 if (!isnull(hosts))
   list[9] = der_encode_list (list:hosts);
 else
   list[9] = NULL;

 return der_encode_sequence (seq:list);
}


#---------------------------------------------------------#
# Function    : kerberostime                              #
# Description : Return KerberosTime Format                #
#               YYYYMMDDHHMMSSZ (Z = UTC time)            #
#---------------------------------------------------------#

function kerberostime()
{
 local_var tmp,time,conv,field;

 time = localtime(unixtime(),utc:TRUE);
 tmp = string (time["year"]);
 foreach field (make_list("mon", "mday", "hour", "min", "sec"))
 {
  conv = string (time[field]);
  if (strlen (conv) == 1)
    conv = "0" + conv;
  tmp += conv;
 }
 tmp += "Z";
 
 return tmp;
}

#---------------------------------------------------------#
# Function    : der_encode_asreq                          #
# Description : Return der encoded AS-REQ                 #
#---------------------------------------------------------#
#                                                         #
# AS-REQ ::= [APPLICATION 10] KDC-REQ                     #
#                                                         #
# KDC-REQ ::= SEQUENCE {                                  #
#   pvno     [1] INTEGER,                                 #
#   msg-type [2] INTEGER,                                 #
#   padata   [3] SEQUENCE OF PA-DATA OPTIONAL,            #
#   req-body [4] KDC-REQ-BODY                             #
# }                                                       #
#                                                         #
# PA-DATA ::= SEQUENCE {                                  #
#   padata-type  [1] INTEGER,                             #
#   padata-value [2] OCTET STRING,                        #
# }                                                       #
#                                                         #
# padata-type     ::= PA-ENC-TIMESTAMP                    #
# padata-value    ::= EncryptedData -- PA-ENC-TS-ENC      #
#                                                         #
# PA-ENC-TS-ENC ::= SEQUENCE {                            #
#   patimestamp [0] KerberosTime, -- client's time        #
#   pausec      [1] INTEGER OPTIONAL                      #
# }                                                       #
#                                                         #	    
#---------------------------------------------------------#
function der_encode_asreq (principal,realm, padata)
{
 local_var req_body, encoded, host,  request, service;
 
 
 service = der_encode_name (type:2, name1:"krbtgt", name2:realm);
 req_body = der_encode_kdc_req_body (principal:principal, realm:realm, service:service);
 
 encoded = der_encode_kdcreq (pvno:5, msg_type:0x0A, list:padata, req_body:req_body);

 return der_encode (tag:0x6A, data:encoded);
}



#---------------------------------------------------------#
# Function    : der_decode_krberror                       #
# Description : Return info in KRB_ERROR                  #
#---------------------------------------------------------#
# KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {         #
#   pvno            [0] INTEGER (5),                      #
#   msg-type        [1] INTEGER (30),                     #
#   ctime           [2] KerberosTime OPTIONAL,            #
#   cusec           [3] Microseconds OPTIONAL,            #
#   stime           [4] KerberosTime,                     #
#   susec           [5] Microseconds,                     #
#   error-code      [6] Int32,                            #
#   crealm          [7] Realm OPTIONAL,                   #
#   cname           [8] PrincipalName OPTIONAL,           #
#   realm           [9] Realm -- service realm --,        #
#   sname           [10] PrincipalName -- service name --,#
#   e-text          [11] KerberosString OPTIONAL,         #
#   e-data          [12] OCTET STRING OPTIONAL            #
#   }                                                     #
#---------------------------------------------------------#
function der_decode_krberror(data)
{
  local_var buf, cname, crealm, der, err_code, err_text, err_data;
  local_var kvno, msg_type, pvno, seq, sname, srealm, ret, tmp;
 
  ret = NULL;
  buf = der_decode (data:data);
  if (isnull(buf) || (buf[0] != 0x7E))
    return NULL;
 
  # Data are in SEQUENCE
  seq = der_parse_sequence (seq:buf[1], num:13, list:FALSE);
  if (isnull(seq))
    return NULL;

  # PVNO == 5
  pvno = der_parse_int (i:seq[0]);
  if (isnull(pvno) || (pvno != 5))
    return NULL;

  # MSG-Type == KRB-ERROR
  msg_type = der_parse_int (i:seq[1]);
  if (isnull(msg_type) || (msg_type != 30))
    return NULL;

  # Error code
  err_code = der_parse_int (i:seq[6]);
  if (isnull(err_code))
    return NULL;

  # Client realm; OPTIONAL
  if(seq[7])
  {
    crealm = der_parse_data(tag:0x1b, data:seq[7]);
    if(isnull(crealm))
      return NULL;
  }

  # Client principal name; OPTIONAL
  if(seq[8])
  {
    tmp = krb_parse_principal_name(data:seq[8]);
    if(isnull(tmp)) 
      return NULL;
    cname = tmp[1]; 
  }

  # Service realm
  if(isnull(seq[9])) return NULL;
  srealm = der_parse_data(tag:0x1b, data:seq[9]);
  if(isnull(srealm))return NULL;

  # Service principal name
  if(isnull(seq[10])) return NULL;
  tmp = krb_parse_principal_name(data:seq[10]);
  if(isnull(tmp)) return NULL;
  sname = tmp[1]; 

  # e-text; OPTIONAL
  if(seq[11])
  {
    err_text = der_parse_data(tag:0x1b, data:seq[11]);
  }  

  # e-data; OPTIONAL
  if(seq[12])
  {
    # Implementation defined error data
    err_data = der_parse_octet_string(string: seq[12]);
 
    # KDC_ERR_PREAUTH_REQUIRED
    # RFC 4120 mandates a SEQUENCE OF PA-DATA for KDC_ERR_PREAUTH_REQUIRED 
    if(err_code == 25)
      err_data = krb_parse_padata(data:err_data); 
    
   if(isnull(err_data)) return NULL;
  } 

  ret[0]  = err_code;
  ret[1]  = err_text;
  ret[2]  = err_data;
  ret[3]  = srealm;
  ret[4]  = sname;;
  ret[5]  = crealm;
  ret[6]  = cname; 

  return ret;
  
}


#---------------------------------------------------------#
# Function    : der_decode_kdcrep                         #
# Description : Return der session key and Ticket         #
#---------------------------------------------------------#
#                                                         #
# AS-REP ::=    [APPLICATION 11] KDC-REP                  #
# KDC-REP ::=   SEQUENCE {                                #
#   pvno            [0]   INTEGER,                        #
#   msg-type        [1]   INTEGER,                        #
#   padata          [2]   SEQUENCE OF PA-DATA OPTIONAL,   #
#   crealm          [3]   Realm,                          #
#   cname           [4]   PrincipalName,                  #
#   ticket          [5]   Ticket,                         #
#   enc-part        [6]   EncryptedData                   #
# }                                                       #
#                                                         #
# EncryptedData ::=   SEQUENCE {                          #
#   etype           [0]   INTEGER, -- EncryptionType      #
#   kvno            [1]   INTEGER OPTIONAL,               #
#   cipher          [2]   OCTET STRING -- ciphertext      #
# }                                                       #
#                                                         #
# EncASRepPart ::=    [APPLICATION 25] EncKDCRepPart      #
# EncKDCRepPart ::=   SEQUENCE {                          #
#   key             [0]   EncryptionKey,                  #
#   last-req        [1]   LastReq,                        #
#   nonce           [2]   INTEGER,                        #
#   key-expiration  [3]   KerberosTime OPTIONAL,          #
#   flags           [4]   TicketFlags,                    #
#   authtime        [5]   KerberosTime,                   #
#   starttime       [6]   KerberosTime OPTIONAL,          #
#   endtime         [7]   KerberosTime,                   #
#   renew-till      [8]   KerberosTime OPTIONAL,          #
#   srealm          [9]   Realm,                          #
#   sname           [10]  PrincipalName,                  #
#   caddr           [11]  HostAddresses OPTIONAL          #
# }                                                       #
#                                                         #
#---------------------------------------------------------#
# ret[0] = der-encoded ticket
# ret[1] = session key
# ret[2] = der-encoded client realm   
# ret[3] = der-encoded client name   
# ret[4] = encryption type the session key is meant to be used with   
# ret[5] = ticket expiration time   
# ret[6] = der-encoded padata; can be NULL   
function der_decode_kdcrep (type,password, data, real_key)
{
 local_var buf,pvno,msg_type,pa_data,crealm,cname,ticket,enc_part,kvno,seq,enc_type,encrypted;
 local_var decrypted, enc_key, enc_types, key, padata;
 local_var endtime,resp, realm, principal, salt, s2kparams;
 
 resp = NULL;

 buf = der_decode (data:data);
 if (isnull(buf) || ((buf[0] != 0x6B) && (buf[0] != 0x6D)))
   return NULL;
 
 # Data are in SEQUENCE
 seq = der_parse_sequence (seq:buf[1], num:7, list:FALSE);
 if (isnull(seq))
   return NULL;

 # PVNO == 5
 pvno = der_parse_int (i:seq[0]);
 if (isnull(pvno) || (pvno != 5))
   return NULL;

 # MSG-Type == AS-REP | TGS-REP
 msg_type = der_parse_int (i:seq[1]);
 if (isnull(msg_type) || (msg_type != type))
   return NULL;

 # (OPTIONAL) padata; alternative salt can be specified here by the KDC 
 padata = seq[2];
 resp[6] = padata; 
  
 # crealm
 crealm = seq[3];
 if (!crealm) return NULL;
 resp[2] = crealm;

 # cname 
 cname = seq[4];
 if (!cname) return NULL;
 resp[3] = cname;

 # TGT 
 ticket = seq[5];
 if (!ticket) return NULL;
 resp[0] = ticket;

 # enc-part 
 enc_part = seq[6];
 if (!enc_part) return NULL;
   
 # ENC-Part is a SEQUENCE
 seq = der_parse_sequence (seq:enc_part, num:3, list:FALSE);
 if (isnull(seq)) 
   return NULL;

 # Encryption type
 enc_type = der_parse_int (i:seq[0]);
 if (isnull(enc_type) || (supported_encryption_type(type:enc_type) == FALSE))
   return NULL;

 # Check enc_types in padata; KDC can specify alternative salt and s2kparams in a PADATA-ETYPE-INFO2 
 salt = s2kparams = NULL;
 if(padata)
 {
    enc_types =  krb_get_enctypes_from_padata(data:padata);
    # It should be only one enctype and match the enc-type used to encrypt the 'ENC-Part'
    if(max_index(enc_types) == 1 && enc_types[0][0] == enc_type)
    {
      salt      = enc_types[0][1];
      s2kparams = enc_types[0][2];
    }
 }

 # (OPTIONAL) Kvno
 # We should not check the kvno; seems kvno changes when the principal changes password 
 # 
 #kvno = der_parse_int (i:seq[1]);
 #if (kvno && ((kvno != 2) && (kvno != 1) && (kvno != 3)))
 #  return NULL;

 # encrypted data
 encrypted = der_parse_octet_string (string:seq[2]);
 if (!encrypted)
   return NULL;

 # We have enc-part in _encrypted[1] here.

 realm = der_parse_data(tag:0x1b, data:crealm);
 seq = der_parse_sequence (seq:cname, num:5, list:FALSE);
 if (isnull(seq))
   return NULL;
 seq = der_parse_sequence (seq:seq[1], num:5, list:TRUE);
 if (isnull(seq))
   return NULL;
 principal = der_parse_data(tag:0x1b, data:seq[1]);

 # Compute key from password
 if(isnull(salt)) salt = realm + principal; # no salt = default salt
 if(! real_key)
  key = krb_string_to_key(enc_type: enc_type, password:password, salt: salt, s2kparams: s2kparams); 
 else
  key = password;

 # enc-part is either EncASRepPart or EncTGSRepPart
 # RFC 4120, section 5.4.2 says about the enc-part:
 #     Compatibility note: Some implementations unconditionally send an
 #     encrypted EncTGSRepPart (application tag number 26) in this field
 #     regardless of whether the reply is a AS-REP or a TGS-REP.  In the
 #     interest of compatibility, implementors MAY relax the check on the
 #     tag number of the decrypted ENC-PART.
 # 
 # if the reply is AS-REP,  the key usage number used to encrypt the enc-part is 3 (section 7.5.1).
 # if the reply is TGS-REP, the key usage number used to encrypt the enc-part is 8 (section 7.5.1).
 # We don't know which reply is the kdc reply until we successfully decrypt the reply, which requires the correct key usage number.
 # This can create a catch-22 situation, here we try both key usage numbers 8 and 3
 decrypted = kerberos_decrypt(key:key, type:8, data:encrypted, enc_type:enc_type);
 if (isnull(decrypted))
 {
    decrypted = kerberos_decrypt(key:key, type:3, data:encrypted, enc_type:enc_type);
    if(isnull(decrypted))return NULL;
 }
 enc_part = der_decode (data:decrypted);
 if (isnull(enc_part) || ((enc_part[0] != 0x79) && (enc_part[0] != 0x7A)))
   return NULL;

 enc_part = der_parse_sequence (seq:enc_part[1], num:12, list:FALSE);
 if (isnull (enc_part))
   return NULL;

 enc_key = der_parse_sequence (seq:enc_part[0], num:2, list:FALSE);
 if (isnull (enc_key))
   return NULL;

 # We parse encryption key
 
 # Encryption type
 enc_type = der_parse_int (i:enc_key[0]);
 if (isnull (enc_type) || (supported_encryption_type(type:enc_type) == FALSE))
   return NULL;

 resp[4] = enc_type;

 # Encryption key
 enc_key = der_parse_octet_string (string:enc_key[1]);
 if (isnull (enc_key))
   return NULL;
 
 # We store the session key
 resp[1] = enc_key;

 # Ticket endtime
 if(isnull(enc_part[7])) return NULL;
 endtime = der_parse_data(tag:0x18, data: enc_part[7]); 
 if(isnull(endtime)) return NULL;
 resp[5] = endtime; 

 return resp;
}


#---------------------------------------------------------#
# Function    : der_decode_asrep                          #
# Description : Return der decoded AP-REP                 #
#---------------------------------------------------------#

function der_decode_asrep (password, data)
{
 return der_decode_kdcrep (type:0x0B, password:password, data:data, real_key:FALSE);
}


#---------------------------------------------------------#
# Function    : der_decode_tgsrep                         #
# Description : Return der decoded TGS-REP                #
#---------------------------------------------------------#

function der_decode_tgsrep (session, data)
{
 return der_decode_kdcrep (type:0x0D, password:session[1], data:data, real_key:TRUE);
}


#---------------------------------------------------------#
# Function    : der_encode_apreq                          #
# Description : Return der encoded AP-REQ                 #
#---------------------------------------------------------#

function der_encode_apreq (session, req_body, type, _checksum, _seqnum, options)
{
 local_var list, encoded, authenticator, authenticators, checksum, auth, realm, principal, seq, cksum;

 authenticator = authenticators = checksum = NULL;

# checksum[0] = der_encode_int (i:-138);
# checksum[1] = der_encode (tag:0x04, data:rc4_hmac_checksum(key:session[1],type:raw_dword(d:6),data:req_body));
 
 realm = der_parse_data(tag:0x1b, data:session[2]);
 seq = der_parse_sequence (seq:session[3], num:5, list:FALSE);
 if (isnull(seq))
   return NULL;
 seq = der_parse_sequence (seq:seq[1], num:5, list:TRUE);
 if (isnull(seq))
   return NULL;
 principal = der_parse_data(tag:0x1b, data:seq[1]);

 if(isnull(options))
  options = der_encode (tag:0x03, data:raw_string (0x00,0x20,0x00,0x00,0x00));
 else
  options = der_encode (tag: 0x03, data: options);
 
 authenticator[0] = der_encode_int(i:5);
 authenticator[1] = session[2];
 authenticator[2] = session[3];

 if (!isnull(req_body))
 {
  cksum = kerberos_checksum(key:session[1],type:6,data:req_body,enc_type:session[4]);

  checksum[0] = der_encode_int (i:get_checksum_type(enc_type:session[4]));
  checksum[1] = der_encode (tag:0x4, data:cksum);

  authenticator[3] = der_encode_sequence (seq:checksum);
 }
 else if (!isnull(_checksum))
  authenticator[3] = _checksum;
 else
  authenticator[3] = NULL;
 authenticator[4] = der_encode_int(i:0);
 authenticator[5] = der_encode_time (time:kerberostime());

 if (!isnull(_seqnum))
 {
  authenticator[6] = NULL;
  authenticator[7] = der_encode_int32 (i:_seqnum);
 }

 auth = der_encode_sequence (seq:authenticator);

 authenticators = der_encode_crypt (key:session[1], type:type, data:der_encode (tag:0x62, data:auth), enc_type:session[4]);


 list = NULL;

 list[0] = der_encode_int(i:5); # Pvno = 5
 list[1] = der_encode_int(i:0x0E); # MSG-Type = AP-REQ
 list[2] = options;
 list[3] = session[0];
 list[4] = authenticators;

 encoded = der_encode_sequence (seq:list);

 return der_encode (tag:0x6E, data:encoded);
}


#---------------------------------------------------------#
# Function    : der_encode_tgsreq                         #
# Description : Return der encoded TGS-REQ                #
#---------------------------------------------------------#

function der_encode_tgsreq (session,name)
{
 local_var realm, req_body, encoded, padata, service, apreq;

 realm = der_decode (data:session[2]);
 #service = der_encode_name (type:3, name1:"host", name2:name);  # Microsoft uses "cifs" for "host"
 service = krb_encode_principal(type: 3, name: name);
 req_body = der_encode_kdc_req_body (realm:realm[1], service:service);
 
 apreq = der_encode_apreq (session:session,req_body:req_body,type:7, options: raw_string(0x00, 0x00, 0x00, 0x00, 0x00));
 padata = der_encode_padata (type:1, value:apreq);

 encoded = der_encode_kdcreq (pvno:5, msg_type:0x0C, list:padata, req_body:req_body);

 return der_encode (tag:0x6C, data:encoded);
}



#---------------------------------------------------------#
# Function    : der_encode_negtokeninit                   #
# Description : Return der encoded NegTokenInit           #
#---------------------------------------------------------#
#                                                         #
# NegTokenInit ::= SEQUENCE {                             #
#   mechTypes     [0]  MechTypeList  OPTIONAL,            #
#   reqFlags      [1]  ContextFlags  OPTIONAL,            #
#   mechToken     [2]  OCTET STRING  OPTIONAL,            #
#   mechListMIC   [3]  OCTET STRING  OPTIONAL             #
# }                                                       #
#                                                         #	    
#---------------------------------------------------------#

function der_encode_negtokeninit (mechtypes, reqflags, mechtoken, mechlistmic)
{
 local_var seq, encoded, list, negtokeninit, spnego_oid;

 encoded = list = NULL;
 
 if (mechtypes)
   list[0] = mechtypes;

 if (reqflags)
   list[1] = reqflags;

 if (mechtoken)
   list[2] = mechtoken;

 if (mechlistmic)
   list[3] = mechlistmic;

 seq = der_encode_sequence (seq:list);
  
 # NegTokenInit Tag = 0xA0
 negtokeninit = der_encode (tag:0xA0, data:seq);

 # SPNEGO OID 
 spnego_oid = der_encode_oid (oid:"1.3.6.1.5.5.2");

 # Application Constructed Object Tag = 0x60
 return der_encode (tag:0x60, data: spnego_oid + negtokeninit);
}


#---------------------------------------------------------#
# Function    : der_parse_spnego_init                     #
# Description : Return der decoded SPNEGO BLOB            #
#---------------------------------------------------------#

function der_parse_spnego_init (sdata)
{
 local_var tmp, data, oid, list, seq, mechtypes, mechseq, mechlistmic;
 local_var negtokeninit;

 data = der_parse_data (tag:0x60, data:sdata);
 if (isnull(data))
   return NULL;

 list = der_parse_list (list:data);
 if (isnull(list) || (list[0] != 2))
   return NULL;
 
 oid = der_parse_oid (oid:list[1]);
 if (!oid || (oid != "1.3.6.1.5.5.2"))
   return NULL;
 
 negtokeninit = NULL;
 negtokeninit[0] = negtokeninit[1] = negtokeninit[2] = negtokeninit[4] = NULL; 
 
 # negTokenInit
 data = der_parse_data (tag:0xA0, data:list[2]);
 if (data)
 {
  seq = der_parse_sequence (seq:data, num:4, list:FALSE);
  if (isnull(seq))
    return NULL;

  #mechType
  if (seq[0] != NULL)
  {
   mechtypes = der_parse_list_oid (list:seq[0]);
   if (!mechtypes)
     return NULL;

   negtokeninit[0] = mechtypes;
  }
 
  #mechListMIC
  if (seq[3] != NULL)
  {
   mechseq = der_parse_sequence (seq:seq[3], num:1, list:FALSE);
   if (isnull (mechseq))
     return NULL;
  
   tmp = der_decode (data:mechseq[0]);
   if (isnull(tmp) || (tmp[0] != 0x1B))
     return NULL;

   mechlistmic = tmp[1];

   negtokeninit[3] = mechlistmic;
  }
 }
 else
  return NULL;
  
 return negtokeninit;
}


#---------------------------------------------------------#
# Function    : der_parse_spnego_resp                     #
# Description : Return der decoded SPNEGO BLOB            #
#---------------------------------------------------------#

function der_parse_spnego_resp (sdata)
{
 local_var data, seq, negresult, supportedmech, responsetoken;
 local_var negtokentarg;
 
 negtokentarg = NULL;
 negtokentarg[0] = negtokentarg[1] = negtokentarg[2] = negtokentarg[3] = NULL;
 
 data = der_parse_data (tag:0xA1, data:sdata);
 if (isnull(data))
   return NULL;
  
 seq = der_parse_sequence (seq:data, num:4, list:FALSE);
 if (isnull(seq))
   return NULL;

 #negresult
 if (seq[0] != NULL)
 {
  negresult = der_parse_data (tag:0x0A,data:seq[0]);
  if (isnull (negresult))
    return NULL;

  negresult = ord(negresult[0]);

  negtokentarg[0] = negresult;
 }
 
 if (seq[1] != NULL)
 {
  supportedmech = der_parse_oid (oid:seq[1]);
  if (!supportedmech)
    return NULL;

  negtokentarg[1] = supportedmech;
 }
 
 if (seq[2] != NULL)
 {
  responsetoken = der_parse_data (tag:0x04, data:seq[2]);
  if (!responsetoken)
    return NULL;

  negtokentarg[2] = responsetoken;
 }
 
 return negtokentarg;
}


function acquired_ticket (login, realm, sname, srealm)
{
 local_var client, service;
 
 client   = login + '@' + realm;
 service  = sname + '@' + srealm;
 
 if (get_kb_item ("kerberos/" + client + "/" + service + "/tgs_ticket"))
   return 1;
 else
   return 0;
}

function expired_ticket(session)
{
  local_var endtime, field, now;

  if(isnull(session) || isnull(session[5]))
    return TRUE;

  endtime['year']  = uint(substr(session[5], 0, 3));
  endtime['mon']   = uint(substr(session[5], 4, 5));
  endtime['mday']  = uint(substr(session[5], 6, 7));
  endtime['hour']  = uint(substr(session[5], 8, 9)); 
  endtime['min']   = uint(substr(session[5], 10, 11)); 
  endtime['sec']   = uint(substr(session[5], 12, 13)); 
   
  now = localtime(unixtime() + 300, utc:TRUE);

  foreach field (make_list('year', 'mon', 'mday', 'hour', 'min', 'sec'))
  {
    if(endtime[field] > now[field]) return FALSE;
    if(endtime[field] < now[field]) return TRUE; 
  } 
  # two times are the same
  return TRUE;
}


function save_tgs_session (session, login, realm, sname, srealm)
{
 local_var client, service;
 
 client   = login + '@' + realm;
 service  = sname + '@' + srealm;
 
 replace_kb_item (name: "kerberos/" + client + "/" + service + "/tgs_session_0", value:hexstr(session[0]));
 replace_kb_item (name: "/tmp/kerberos/" + client + "/" + service + "/tgs_session_1", value:hexstr(session[1]));
 replace_kb_item (name: "kerberos/" + client + "/" + service + "/tgs_session_2", value:hexstr(session[2]));
 replace_kb_item (name: "kerberos/" + client + "/" + service + "/tgs_session_3", value:hexstr(session[3]));
 replace_kb_item (name: "kerberos/" + client + "/" + service + "/tgs_session_4", value:session[4]);
 replace_kb_item (name: "kerberos/" + client + "/" + service + "/tgs_session_5", value:session[5]);
 replace_kb_item (name: "kerberos/" + client + "/" + service + "/tgs_ticket", value:1);
}


function _hex2raw(s)
{
 local_var i, j, ret, l;

 s = chomp(s);	# remove trailing blanks, CR, LF...
 l = strlen(s);
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


function load_tgs_session (login, realm, sname, srealm)
{
 local_var session, client, service;
 
 # No ticket 
 if (!acquired_ticket(login:login, realm:realm, sname:sname, srealm: srealm))
   return NULL;

 client   = login + '@' + realm;
 service  = sname + '@' + srealm;

 session[0] = _hex2raw(s:get_kb_item ("kerberos/" + client + "/" + service + "/tgs_session_0"));
 session[1] = _hex2raw(s:get_kb_item ("/tmp/kerberos/" + client + "/" + service + "/tgs_session_1"));
 session[2] = _hex2raw(s:get_kb_item ("kerberos/" + client + "/" + service + "/tgs_session_2"));
 session[3] = _hex2raw(s:get_kb_item ("kerberos/" + client + "/" + service + "/tgs_session_3"));
 session[4] = get_kb_item ("kerberos/" + client + "/" + service + "/tgs_session_4");
 session[5] = get_kb_item ("kerberos/" + client + "/" + service + "/tgs_session_5");

 # Expired ticket
 if(expired_ticket(session:session)) return NULL;

 return session;
}


#---------------------------------------------------------#
# Function    : kerberos_securityblob                     #
# Description : Return kerberos/GSSAPI/SPNEGO blob        #
#---------------------------------------------------------#
function kerberos_securityblob (login,password,realm,host)
{
 local_var ret, mechtypes, mechtoken, apreq,  session, sname, srealm;

 # We only support Microsoft Kerberos
 # mechtypes = der_encode (tag:0x30, data:der_encode_oid (oid:"1.2.840.48018.1.2.2") + der_encode_oid (oid:"1.2.840.113554.1.2.2"));
 mechtypes = der_encode (tag:0x30, data:der_encode_oid (oid:"1.2.840.48018.1.2.2"));

 # SPN must be 'cifs/<host>' when policy "Microsoft network server: Server SPN target name validation level" is set to 
 # a value other than 'off'.
 # If this policy is not disabled or set to 'off', SPN 'host/<host>' can be used 
 sname = 'cifs/' + host; 
 srealm = realm; # We currently only support single realm auth
 session = load_tgs_session(login: login, realm: realm, sname:sname, srealm: srealm);
 if (isnull(session)) 
 {
  session = krb_get_ticket(login: login, password: password, realm: realm, sname: sname, type: "SMB");
  if(isnull(session)) return NULL;
  save_tgs_session(session:session, login: login, realm: realm, sname:sname, srealm:srealm);
 }

 apreq = der_encode_apreq (session:session, type:11);
 
 mechtoken = der_encode_oid (oid:"1.2.840.113554.1.2.2") +
             raw_word (w:1)+
	     apreq;
 mechtoken = der_encode (tag:0x60, data:mechtoken);
 mechtoken = der_encode_octet_string (string:mechtoken);

 # MS KRB5 has no init flags and no mechListMIC
 ret = NULL;
 ret[0] = session[1];
 ret[1] = der_encode_negtokeninit (mechtypes:mechtypes, reqflags:NULL, mechtoken:mechtoken, mechlistmic:NULL);

 return ret;
}

#---------------------------------------------------------#
# Function    : check_kerberos_response                   #
# Description : Return 1 if trusted/accepted              #
#---------------------------------------------------------#

function check_kerberos_response (data, key, realm, principal)
{
 local_var negtokentarg, negresult, supportedmech, responsetoken, init, msg, challenge, kerberosblob, name;
 local_var list, oid, seq, kid, aprep, pvno, msg_type, enc_part, enc_type, encrypted, decrypted, enc_key, ret;

 negtokentarg = der_parse_spnego_resp (sdata:data);
 if (isnull (negtokentarg))
   return NULL;
 
 negresult = negtokentarg[0];
 if (negresult != 0) # Accept Complete
   return NULL;
 
 supportedmech = negtokentarg[1];
 
 if ("1.2.840.48018.1.2.2" >!< supportedmech)
   return NULL;
 
 responsetoken = negtokentarg[2];
 if (!responsetoken)
   return NULL;
 
 kerberosblob = der_parse_data (tag:0x60, data:responsetoken);
 if (isnull (kerberosblob))
   return NULL;

 list = der_parse_list (list:kerberosblob);
 if (isnull (list))
   return NULL;

 if (list[0] != 3)
   return NULL;

 oid = der_parse_oid (oid:list[1]);
 if (!oid || ("1.2.840.113554.1.2.2" >!< oid))
   return NULL;
 
 kid = list[2];
 if (ord(kid[0]) != 2) # AP-REP
   return NULL;
 
 aprep = der_parse_data (tag:0x6F, data:list[3]);
 if (isnull (aprep))
   return NULL;
 
 seq = der_parse_sequence (seq:aprep, num:4, list:FALSE);
 if (isnull (seq))
   return NULL;

 pvno = der_parse_int (i:seq[0]);
 if (isnull (pvno) || (pvno != 5))
   return NULL;
 
 msg_type = der_parse_int (i:seq[1]);
 if (isnull (msg_type) || (msg_type != 15)) # AP-REP
   return NULL;
 
 enc_part = der_parse_sequence (seq:seq[2], num:3, list:NULL);
 if (isnull (enc_part))
   return NULL;

 enc_type = der_parse_int (i:enc_part[0]);
 if (isnull (enc_type) || (supported_encryption_type(type:enc_type) == FALSE))
   return NULL;

 encrypted = der_parse_octet_string (string:enc_part[2]);
 if (isnull (encrypted))
   return NULL;
 
 decrypted = kerberos_decrypt (key:key, type:12, data:encrypted, enc_type:enc_type);
 if (isnull (decrypted))
   return NULL;

 # we need to extract the subkey if present for SMB Signing
 enc_part = der_parse_data (tag:0x7b, data:decrypted);
 if (isnull (enc_part))
   return NULL;

 seq = der_parse_sequence (seq:enc_part, num:4, list:NULL);
 if (isnull (seq))
   return NULL;
 

 ret = NULL;
 ret [0] = 0;

 if (seq[2] != NULL)
 {
  seq = der_parse_sequence (seq:seq[2], num:2, list:NULL);
  if (isnull (seq))
    return NULL;

  enc_type = der_parse_int (i:seq[0]);
  if (isnull (enc_type) || (supported_encryption_type(type:enc_type) == FALSE))
    return NULL;
  
  enc_key = der_parse_octet_string (string:seq[1]);
  if (isnull (enc_key))
   return NULL;

  ret[0] = 1;
  ret[1] = enc_key;
 }

 return ret;
}



#---------------------------------------------------------#
# Function    : raw_ntlmssp_negotiate                     #
# Description : generate NTLMSSP_NEGOCIATE blob           #
#---------------------------------------------------------#

function raw_ntlmssp_negotiate (flags)
{
 local_var ntlmssp;

 if (isnull(flags))
   flags = 0;

 ntlmssp = "NTLMSSP" + raw_string (0x00);
 ntlmssp += raw_dword (d:1); # NTLMSSP_NEGOTIATE
 
 ntlmssp += raw_dword (d:NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_NTLM2 | NTLMSSP_NEGOTIATE_ALWAYS_SIGN | flags);  # Flags
 ntlmssp += ntlmssp_data (data:NULL,offset:0); # workstation domain NULL
 ntlmssp += ntlmssp_data (data:NULL,offset:0); # workstation name NULL
 
 # Version 1.0
 ntlmssp += raw_byte (b:5) + raw_byte (b:1);
 # Version Number = 0
 ntlmssp += raw_word (w:2600);

 # Unknown value
 ntlmssp += raw_string (0x00,0x00,0x00,0x0F);

 return ntlmssp;
}



#---------------------------------------------------------#
# Function    : ntlmssp_negotiate_securityblob            #
# Description : Return NTLMSSP_NEGOCIATE blob             #
#---------------------------------------------------------#

function ntlmssp_negotiate_securityblob ()
{
 local_var mechtypes, mechtoken, ntlmssp, offset;

 mechtypes = der_encode (tag:0x30, data:der_encode_oid (oid:"1.3.6.1.4.1.311.2.2.10"));
 
 ntlmssp = raw_ntlmssp_negotiate ();

 mechtoken = der_encode_octet_string (string:ntlmssp);
 
 return der_encode_negtokeninit (mechtypes:mechtypes, reqflags:NULL, mechtoken:mechtoken, mechlistmic:NULL);
}


#---------------------------------------------------------#
# Function    : raw_ntlmssp_parse_challenge               #
# Description : Return NTLM challenge                     #
#---------------------------------------------------------#

function raw_ntlmssp_parse_challenge (data)
{
 local_var init, msg, d_len, offset, domain, challenge, ret;

 ret = NULL;

 init = substr (data, 0, 7);
 if ("NTLMSSP" >!< init)
   return NULL;
 
 msg = substr (data, 8, 11);
 if ("02000000" >!< hexstr(msg)) # NTLMSSP_CHALLENGE
   return NULL;

 d_len = get_word (blob:data, pos:12);
 offset = get_dword (blob:data, pos:16);

 domain = substr (data, offset, offset+d_len-1);
 challenge = substr (data, 24, 31);

 # blob
 d_len = get_word (blob:data, pos:40);
 offset = get_dword (blob:data, pos:44);

 ret[0] = challenge;
 ret[1] = domain;
 ret[2] = get_dword (blob:data, pos:20);
 if (d_len > 0)
 {
  ret[3] = substr(data, offset, offset+d_len-1);
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : ntlmssp_parse_challenge                   #
# Description : Return NTLM challenge                     #
#---------------------------------------------------------#

function ntlmssp_parse_challenge (data)
{
 local_var negtokentarg, negresult, supportedmech, responsetoken, init, msg, challenge, d_len, offset, domain, ret;
 
 negtokentarg = der_parse_spnego_resp (sdata:data);
 if (isnull (negtokentarg))
   return NULL;
 
 negresult = negtokentarg[0];
 if (negresult != 1) # Accept Incomplete
   return NULL;
 
 supportedmech = negtokentarg[1];
 
 if ("1.3.6.1.4.1.311.2.2.10" >!< supportedmech)
   return NULL;
 
 responsetoken = negtokentarg[2];
 if (!responsetoken)
   return NULL;
 
 if (strlen(responsetoken) < 40)
   return NULL;


 return raw_ntlmssp_parse_challenge (data:responsetoken);

 init = substr (responsetoken, 0, 7);
 if ("NTLMSSP" >!< init)
   return NULL;
 
 msg = substr (responsetoken, 8, 11);
 if ("02000000" >!< hexstr(msg)) # NTLMSSP_CHALLENGE
   return NULL;

 d_len = get_word (blob:responsetoken, pos:12);
 offset = get_dword (blob:responsetoken, pos:16);

 domain = substr (responsetoken, offset, offset+d_len-1);

 challenge = substr (responsetoken, 24, 31);

 ret[0] = challenge;
 ret[1] = domain;

 return ret;
}


#---------------------------------------------------------#
# Function    : ntlmssp_parse_response                    #
# Description : Return NTLM Result                        #
#---------------------------------------------------------#

function ntlmssp_parse_response (data)
{

 local_var negtokentarg, negresult;
 
 negtokentarg = der_parse_spnego_resp (sdata:data);
 if (isnull (negtokentarg))
   return NULL;
 
 negresult = negtokentarg[0];
 return negresult;
}



#---------------------------------------------------------#
# Function    : ntlmssp_data                              #
# Description : Return NTLMSSP data                       #
#               word  data_len                            #
#               word  data_len                            #
#		dword offset_data                         #
#---------------------------------------------------------#

function ntlmssp_data (data,offset)
{
 return raw_word (w:strlen(data)) + raw_word (w:strlen(data)) + raw_dword (d:offset);
}


#---------------------------------------------------------#
# Function    : raw_ntlmssp_auth_securityblob             #
# Description : Return NTLMSSP_AUTH blob                  #
#---------------------------------------------------------#

function raw_ntlmssp_auth_securityblob (password, login, hash, domain, challenge, flags, skey, sblob)
{
 local_var ntlmssp,nt,response;
 local_var hostname,sessionkey,lm,offset,key,ret;

 if (isnull(flags))
   flags = 0;

 sessionkey = lm = nt = NULL;
 hostname = domain;

 # Systems with Extended Security Authentication support NTLMv2 so NTLMv1 is useless here (?) 

 if (login)
 {
  response = LMv2_Response (password:password, login:login, hash:hash, domain:domain, challenge:challenge);
  lm = response[0];
  key = response[1];
  if (sblob)
  {
   response = NTLMv2_Response (password:password, login:login, hash:hash, domain:domain, challenge:challenge, sblob:sblob);
   nt = response[0];
   key = response[1];
  }
 }
 else
 {
  lm = raw_string (0x00);
  key = raw_string (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
 }

 #response = NTLM_Response (password:password, hash:hash, challenge:challenge);
 #nt = response[0];

 offset = 0x48; # First text;
 
 ntlmssp = "NTLMSSP" + raw_string (0x00);
 ntlmssp += raw_dword (d:3); # NTLMSSP_AUTH
 
 # Lan Manager response = NULL
 ntlmssp += ntlmssp_data (data:lm,offset:offset);
 offset += strlen (lm);

 # NTLM Response
 ntlmssp += ntlmssp_data (data:nt,offset:offset);
 offset += strlen(nt);

 # Domain name = NULL
 ntlmssp += ntlmssp_data (data:domain, offset:offset);
 offset += strlen (domain);
 
 # User name
 ntlmssp += ntlmssp_data (data:login, offset:offset);
 offset += strlen (login);

 # Host name = NULL
 ntlmssp += ntlmssp_data (data:hostname, offset:offset);
 offset += strlen (hostname);

 if (!isnull(skey))
 {
  # if we only use LMv2 then XP needs this key to be set to 0.
  # arcfour_setkey(key:raw_string(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0));
  # else the password derived key works fine against 2000/2003/Vista
  # I wonder if this changed was introduced to break samba.
  # However NTLMv2 signature works fine.
  arcfour_setkey(key:key);
  sessionkey = ARCFOUR(data:skey);
 }
 
 # Session Key = NULL
 ntlmssp += ntlmssp_data (data:sessionkey, offset:offset);
 offset += strlen (sessionkey);
 
 ntlmssp += raw_dword (d:NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_NTLM2 | flags); # Flags
 # Version 1.0
 ntlmssp += raw_byte (b:1) + raw_byte (b:0);
 # Version Number = 0
 ntlmssp += raw_word (w:0);

 # Unknown value
 ntlmssp += raw_string (0x00,0x00,0x00,0x0F);

 ntlmssp += lm + nt + domain + login + hostname + sessionkey; 

 ret = NULL;
 ret[0] = ntlmssp;
 ret[1] = key;

 return ret;
}

#---------------------------------------------------------#
# Function    : ntlmssp_auth_securityblob                 #
# Description : Return NTLMSSP_AUTH blob                  #
#---------------------------------------------------------#

function ntlmssp_auth_securityblob (password,login,hash,domain,challenge, flags, skey, sblob)
{
 local_var ntlmssp, responsetoken, ret;

 ret = raw_ntlmssp_auth_securityblob (password:password, login:login, hash:hash, domain:domain, challenge:challenge, flags:flags, skey:skey, sblob:sblob);

 ntlmssp = der_encode_octet_string (string:ret[0]);
 responsetoken = der_encode (tag:0xA2, data:ntlmssp);
 responsetoken = der_encode_list (list:responsetoken);

 ret[0] = ret[1];
 ret[1] = der_encode (tag:0xA1, data:responsetoken); 

 return ret;
}


#---------------------------------------------------------#
# Function    : kerberos_ssh                              #
# Description : Return kerberos blob                      #
#---------------------------------------------------------#
function kerberos_ssh (login,password,realm,host,seqnum)
{
 local_var ret, cksum, checksum, apreq, innercontexttoken, initialcontexttoken, session, sname, srealm;

 sname = 'host/' + host;
 srealm = realm; # We current support single realm auth

 session = load_tgs_session(login: login, realm: realm, sname: sname, srealm: srealm);
 if(isnull(session))
 {
  session = krb_get_ticket(login: login, password: password, realm: realm, sname: sname, type: "SSH");
  if(isnull(session)) return NULL;
  save_tgs_session(session:session, login: login, realm: realm, sname: sname, srealm: srealm);
 }

 cksum = raw_dword (d:16) + # bnd length
         crap (data:raw_string(0),length:16) + #bnd
         raw_dword (d:32|2) + # flags
         
 checksum = NULL;
 checksum[0] = der_encode_int32 (i:0x8003);
 checksum[1] = der_encode (tag:0x04, data:cksum);

 apreq = der_encode_apreq(session:session, type:11, _checksum:der_encode_sequence (seq:checksum), _seqnum:seqnum);

 innercontexttoken = raw_string(0x01,0x00) + apreq;
 initialcontexttoken = der_encode_oid(oid:"1.2.840.113554.1.2.2")+innercontexttoken;

 ret = NULL;
 ret[0] = session[1];
 ret[1] = der_encode (tag:0x60, data:initialcontexttoken);
 ret[2] = session[4];

 return ret;

}
#---------------------------------------------------------#
# Function    : gssapi_ssh_get_mic                        #
# Description : Return gssapi mic                         #
#---------------------------------------------------------#

function gssapi_ssh_get_mic (data, key, seqnum, enc_type)
{
 local_var hash, des_cksum, seq_num, crypted, mic;


 if(! supported_encryption_type(type:enc_type))
  return NULL;
                 
 if(enc_type == 23)
   return gssapi_ssh_get_mic_rc4_hmac(data:data, key:key, seqnum:seqnum);
 else if(enc_type == 18 || enc_type == 17)
   return gssapi_ssh_get_mic_aes(data:data, key:key, seqnum:seqnum, enc_type: enc_type);
 else if (enc_type == 3) # deprecated des-cbc-md5
 {  
  hash = MD5 ( raw_string(0x01,0x01,0x00,0x00,0xFF,0xFF,0xFF,0xFF) +
               data );

  des_cksum = des_cbc_checksum (key:key,data:hash,iv:raw_string(0,0,0,0,0,0,0,0));

  seq_num = raw_dword (d:seqnum) + raw_dword (d:0);

  crypted = des_cbc_encrypt (data:seq_num, key:key, iv:des_cksum, encrypt:1);

  mic = der_encode (tag:0x60, data:der_encode_oid(oid:"1.2.840.113554.1.2.2") + raw_string (0x01,0x01,0x00,0x00,0xFF,0xFF,0xFF,0xFF) + crypted + des_cksum);

  return mic;
 }
}

#---------------------------------------------------------#
# Function    : gssapi_ssh_get_mic_rc4_hmac               #
# Description : Return gssapi mic  for rc4-hmac           #
# see RFC 4757 for details.                               #
#---------------------------------------------------------#
function gssapi_ssh_get_mic_rc4_hmac(data, key, seqnum)
{
  local_var chksum, hdr, kseq, ksign, mic, token;
  
  hdr = raw_string(0x01, 0x01) +            # Token ID
        raw_string(0x11, 0x00) +            # SNG_ALG
        raw_string(0xff, 0xff, 0xff, 0xff); # filler
  
  seqnum = raw_dword (d:seqnum, be: TRUE) + crap(data:'\x00', length:4);
  
  ksign = HMAC_MD5(key: key, data: 'signaturekey\x00');
  
  chksum = MD5(raw_dword (d:15) + hdr + data);
  chksum = HMAC_MD5(key: ksign, data:chksum);
  chksum = substr(chksum, 0, 7);
  
  kseq = HMAC_MD5(key: key, data: raw_dword (d:0));
  kseq = HMAC_MD5(key: kseq, data: chksum);
  
  arcfour_setkey (key: kseq);
  seqnum = ARCFOUR (data:seqnum);
  
  mic = hdr + seqnum + chksum;
  
  # GSSAPI version 1 format
  mic = der_encode (tag:0x60, data:der_encode_oid(oid:"1.2.840.113554.1.2.2") + mic);

  return mic;
  
}

#---------------------------------------------------------#
# Function    : gssapi_ssh_get_mic_aes                    #
# Description : Return gssapi mic for aes-cts-sha96       #
# - See RFC 4121, section 4.2.6.1 for more details        # 
#---------------------------------------------------------#
function gssapi_ssh_get_mic_aes(data, key, seqnum, enc_type)
{
  local_var chksum, hdr, mic, kc;

  hdr = '\x04\x04' +                                # TOKEN ID
        '\x00'+                                     # flags
        '\xff\xff\xff\xff\xff' +                    # filler
         raw_dword(d:seqnum, be:TRUE) + '\x00\x00\x00\x00'; # sequence number
  
  kc = krb_dk_aes(basekey:key, outsize:strlen(key), const:raw_dword(d:25, be:TRUE) + '\x99');
  chksum = HMAC_SHA1(data:data + hdr , key:kc);
  chksum = substr(chksum, 0, 11);

  # Since AES is a "newer" encryption type per RFC 4121, Kerberos GSSAPI version 2 token format MUST be used  
  mic = hdr + chksum;
  
  # Some server will also accept Kerberos GSSAPI version 1 token format
  # mic = der_encode (tag:0x60, data:der_encode_oid(oid:"1.2.840.113554.1.2.2") + mic);

  return mic;
}


#---------------------------------------------------------#
# Function    : check_gssapi_token                        #
# Description : Return 1 if trusted/accepted              #
#---------------------------------------------------------#

function check_gssapi_token (data, key, realm, principal)
{
 local_var list, oid, seq, kid, aprep, pvno, msg_type, enc_part, enc_type, encrypted, decrypted, enc_key, kerberosblob, ret;

  
 kerberosblob = der_parse_data (tag:0x60, data:data);
 if (isnull (kerberosblob) || (strlen(kerberosblob)<14))
   return NULL;

 list = NULL;
 list[1] = substr(kerberosblob,0,10);
 list[2] = substr(kerberosblob,11,12);
 list[3] = substr(kerberosblob,13,strlen(kerberosblob)-1);

 oid = der_parse_oid (oid:list[1]);
 if (!oid || ("1.2.840.113554.1.2.2" >!< oid))
   return NULL;
 
 kid = list[2];
 if (ord(kid[0]) != 2) # AP-REP
   return NULL;
 
 aprep = der_parse_data (tag:0x6F, data:list[3]);
 if (isnull (aprep))
   return NULL;
 
 seq = der_parse_sequence (seq:aprep, num:4, list:FALSE);
 if (isnull (seq))
   return NULL;

 pvno = der_parse_int (i:seq[0]);
 if (isnull (pvno) || (pvno != 5))
   return NULL;
 
 msg_type = der_parse_int (i:seq[1]);
 if (isnull (msg_type) || (msg_type != 15)) # AP-REP
   return NULL;
 
 enc_part = der_parse_sequence (seq:seq[2], num:3, list:NULL);
 if (isnull (enc_part))
   return NULL;

 enc_type = der_parse_int (i:enc_part[0]);
 if (isnull (enc_type) || (supported_encryption_type(type:enc_type) == FALSE))
   return NULL;

 encrypted = der_parse_octet_string (string:enc_part[2]);
 if (isnull (encrypted))
   return NULL;
 
 decrypted = kerberos_decrypt (key:key, type:12, data:encrypted,  enc_type:enc_type);
 if (isnull (decrypted))
   return NULL;

 # we need to extract the subkey if present for SMB Signing
 enc_part = der_parse_data (tag:0x7b, data:decrypted);
 if (isnull (enc_part))
   return NULL;

 seq = der_parse_sequence (seq:enc_part, num:4, list:NULL);
 if (isnull (seq))
   return NULL;
 

 ret = NULL;
 ret [0] = 0;

 if (seq[2] != NULL)
 {
  seq = der_parse_sequence (seq:seq[2], num:2, list:NULL);
  if (isnull (seq))
    return NULL;

  enc_type = der_parse_int (i:seq[0]);
  if (isnull (enc_type) || (supported_encryption_type(type:enc_type) == FALSE))
    return NULL;
  
  enc_key = der_parse_octet_string (string:seq[1]);
  if (isnull (enc_key))
   return NULL;

  ret[0] = 1;
  ret[1] = enc_key;
 }

 return ret;
}


##
# Kerberos DK function for AES
#
# @param basekey base key computed from the PBKDF2 function
# @param outsize derived key size in bytes
# @param const well-known constant
# @return a AES key; NULL on error
# @remark
#   - See RFC 3961, section 5.1 for more details
#
##
function krb_dk_aes(basekey, outsize, const)
{
  local_var data, keymat, ret, total;

  # Kerberos only support 128-bit and 256-bit AES keys
  if(outsize != 16 && outsize != 32)
    return NULL;

  # Fold the well-known constant if it's less than a AES block
  if(strlen(const) < 16)
    const = nfold(data:const, flen:16);

  keymat = NULL;
  data = const;
  while (strlen(keymat) < outsize)
  { 
    ret = aes_cbc_encrypt(data:data, key:basekey, iv:crap(data:'\x00',length:16));
    if(isnull(ret)) return NULL;
    keymat += ret[0];
    data = ret[0];
  }

  return substr(keymat, 0, outsize - 1);
  
} 

##
# Converts a password to a Kerberos AES key
#
# @param password user password
# @param salt salt to feed into the PBDKF2 key derivation routine
# @param iter iterations feed into the PBDKF2 key derivation routine  
# @param keysize requested AES key size in bytes
# @return AES key; NULL on error
#
##
function krb_string_to_key_aes(password, salt, iter, keysize)
{
  local_var tkey;

  if(isnull(password) || isnull(salt)) return NULL;
  if(keysize != 16 && keysize != 32)
    return NULL;
  if(isnull(iter))  iter = 4096;

  tkey = pbkdf2(p:password, s:salt, c:iter, dklen:keysize);
  return krb_dk_aes(basekey:tkey, outsize:keysize, const: 'kerberos');
   
}

##
# Encrypts data using AES 
#
# @param data data to be encrypted
# @param key base encryption key
# @param keyusage key usage number
# @return encrypted data; NULL on error
# @remark
#   - See RFC 3961, section 5.3 for more details
##
function krb_aes_encrypt(data, key, keyusage)
{
  local_var conf, hmac, i, iv, ke, ki, out, ret;

  # Get a confounder of block size
  conf = NULL;
  for (i=0; i<16; i++)
    conf += raw_byte(b:rand()%256);
 
  # Plaintext to the encryption and hmac routines 
  data = conf + data;

  # Derive encryption key
  ke = krb_dk_aes(basekey:key, outsize:strlen(key), const:keyusage + '\xAA');

  # Encrypt plaintext
  iv = crap(data:'\x00', length:16);  
  ret = aes_cbc_cts_encrypt(data: data, key:ke, iv:iv); 
  if(isnull(ret)) return NULL;
  
  # Derive hmac key
  ki = krb_dk_aes(basekey:key, outsize:strlen(key), const:keyusage + '\x55');

  # Compute hmac over plaintext
  hmac = HMAC_SHA1(data:data, key:ki);

  # Append hmac to ciphertext
  out = ret[0] + substr(hmac, 0, 11);

  return out;  
}

##
# Decrypts data using AES 
#
# @param data data to be decrypted 
# @param key base encryption key
# @param keyusage key usage number
# @return decrypted data; NULL on error
# @remark
#   - See RFC 3961, section 5.3 for more details
##
function krb_aes_decrypt(data, key, keyusage)
{
  local_var c1, h1, hmac, iv, ke, ki, out, p1, ret;

  # Check ciphertext length
  # confounder + data + hmac
  if(strlen(data) < 16 + 1 + 12) return NULL;

  # Split data into ciphertext and hmac
  c1 = substr(data, 0, strlen(data) - 13);
  h1 = substr(data, strlen(data) - 12);

  # Derive decryption key
  ke = krb_dk_aes(basekey:key, outsize:strlen(key), const:keyusage + '\xAA');

  # Decrypt ciphertext
  iv = crap(data:'\x00', length:16);  
  ret = aes_cbc_cts_decrypt(data:c1, key:ke, iv:iv); 
  if(isnull(ret)) return NULL;
  p1 = ret[0];

  # Derive hmac key
  ki = krb_dk_aes(basekey:key, outsize:strlen(key), const:keyusage + '\x55');

  # Compute hmac 
  hmac = HMAC_SHA1(data:p1, key:ki);
 
  # Compare received hmac with computed hmac
  if(h1 != substr(hmac, 0, 11))
    return NULL; 

  # Extract plaintext if hmac check passed
  out = substr(p1, 16);
  return out;  
}

##
# Computes checksum using Kerberos AES profile
#
# @param data data to be decrypted 
# @param key base encryption key
# @param keyusage key usage number
# @return encrypted data; NULL on error
# @remark
#   - See RFC 3961, section 5.3 for more details
##
function krb_aes_checksum(data, key, keyusage)
{
  local_var hmac, kc;

  # Derive key for checksum computation
  kc = krb_dk_aes(basekey:key, outsize:strlen(key), const:keyusage + '\x99');

  # Compute chechksum 
  hmac = HMAC_SHA1(data:data, key:kc);
  return substr(hmac, 0, 11); 
}

##
# Parses a list of PA-DATA objects 
#
# @param data DER-encoded data representing a SEQUENCE OF PA-DATA
# @return a list of structures; or NULL on error
#       ret[i]['type']  - padata type
#       ret[i]['value'] - padata value in raw bytes
#
# @remark
#
# PA-DATA         ::= SEQUENCE {
#      -- NOTE: first tag is [1], not [0]
#      padata-type     [1] Int32,
#      padata-value    [2] OCTET STRING -- might be encoded AP-REQ
# }
#
##
function krb_parse_padata(data)
{
  local_var i, list, padata, seq, ret;

  # padata is SEQUENCE OF PA-DATA
  list = der_parse_sequence (seq:data,list:TRUE);
  if(isnull(list)) return NULL;
  
  for (i = 0; i < list[0]; i++)
  {
    seq = der_parse_sequence (seq:list[i + 1],num:3, list:FALSE); 
    if(isnull(seq)) return NULL;
    
    padata[0]  = der_parse_int(i:seq[1]);
    padata[1] = der_parse_octet_string(string:seq[2]); # may or may not DER encoded
    ret[i] = padata;
  } 
 
  return ret;
}

##
# Finds a particular padata type in a list of PA-DATA objects
#
# @param data DER-encoded data representing a SEQUENCE OF PA-DATA
# @param type target padata type
# @return first instance of PA-DATA of type <type>; or NULL if not found or on error 
#   ret[0] - padata-type
#   ret[1] - padata-value
# 
##
function krb_padata_lookup(data, type)
{
  local_var padata; 
 
  # Parse it if padata sequence is raw data 
  if(typeof(data) == 'data')
    data = krb_parse_padata(data:data);

  if(isnull(data)) return NULL;
   
  foreach padata (data)
  {
    if(padata[0] == type)
      return padata;
  } 
  return NULL;
}

##
# Parses a ETYPE-INFO2-ENTRY object
#
# @param data DER-encoded data representing a ETYPE-INFO2-ENTRY object
# @return parsed ETYPE-INFO2-ENTRY; or NULL on error
#         ret[0] = encryption type ID
#         ret[1] = optional salt to the string_to_key function for the encryption type 
#         ret[2] = optional s2kparams to the string_to_key function for the encryption type
# @remark
#
# ETYPE-INFO2-ENTRY       ::= SEQUENCE {
#        etype           [0] Int32,
#        salt            [1] KerberosString OPTIONAL,
#        s2kparams       [2] OCTET STRING OPTIONAL
# }
##
function krb_parse_etype_info2_entry(data)
{
  local_var seq, info;

  seq = der_parse_sequence(seq: data, num: 3, list: FALSE);
  if(isnull(seq)) return NULL;

  # enc-type
  if(isnull(seq[0])) return NULL;
  info[0] = der_parse_int(i: seq[0]);

  # salt, OPTIONAL
  if(seq[1])
    info[1] = der_parse_data(tag: 0x1b, data: seq[1]);
  
  # s2kparams, OPTIONAL
  if(seq[2])
    info[2] = der_parse_octet_string(string:seq[0]);
   
  return info; 
}

##
# Parses a ETYPE-INFO2 object
# 
# @param data DER-encoded data representing a ETYPE-INFO2 object
# @return a list of parsed ETYPE-INFO2-ENTRYs; or NULL on error
# @remark  
#   - See return value of krb_parse_etype_info2_entry()
#
# ETYPE-INFO2             ::= SEQUENCE SIZE (1..MAX) OF ETYPE-INFO2-ENTRY
##
function krb_parse_etype_info2(data)
{
  local_var entry, i, list, ret;

  list = der_parse_sequence(seq:data, list: TRUE);
  if(isnull(list)) return NULL;
  for(i = 0; i < list[0]; i++)
  {
    entry = krb_parse_etype_info2_entry(data: list[i+1]);
    if(isnull(entry)) return NULL;
    ret[i] = entry;
  }
  return ret;
}

##
# Gets encryption types from a list of PA-DATA objects
#
# @param data DER-encoded data representing a SEQUENCE OF PA-DATA
# @return see krb_parse_etype_info2()
#
##
function krb_get_enctypes_from_padata(data)
{
  local_var etype_info2;

  etype_info2 = krb_padata_lookup(data:data, type: 19);
  if(isnull(etype_info2)) return NULL;

  return krb_parse_etype_info2(data:etype_info2[1]);
}

##
# Encodes a principal name
#
# @param type name type
# @param name name string in form of component_1/component_2/component_n or a list of components
# @return DER-encoded principal
#
##
function krb_encode_principal (type, name)
{
 local_var i, list, names;

 if (isnull (name)) 
   return NULL;

 # name in 'component1/component2...' 
 if(typeof(name) == 'data' || typeof(name) == 'string')
 {
   # single component
   if ('/' >!< name) list[0] = name;
   # multiple components
   else
    list = split(name, sep:'/', keep:FALSE);
 }

 names = NULL;    
 for (i = 0; i < max_index(list); i++)
 { 
  names += der_encode_string (string:list[i]);
 }
 
 list = NULL;
 list[0] = der_encode_int (i:type);
 list[1] = der_encode_list (list:names);

 return der_encode_sequence (seq:list); 
}

##
# Parses a Kerberos principal  
#
# @param data DER-encoded PrincipalName
# @param concat whether concatenate components in the name-string part of the PrincipalName
# @return a list or NULL on error
#   ret[0] - type of the principal name
#   ret[1] - if concat is non-zero, it holds the name in form of 'component_1/component_2/.../component_n' 
#          - if concat is zero, it holds a list of components in the name
#
# @remark PrincipalName is defined as:
#   PrincipalName   ::= SEQUENCE {
#           name-type       [0] Int32,
#           name-string     [1] SEQUENCE OF KerberosString
#   }
#
##
function krb_parse_principal_name(data, concat)
{
  local_var i, comp, comp_list, fname, list, seq, ret, type;

  seq = der_parse_sequence(seq:data, num:2, list:FALSE);
  if(isnull(seq) || isnull(seq[0]) || isnull(seq[1]))
    return NULL;

  if(isnull(concat)) concat = TRUE;
  # name type
  type = seq[0];
  
  # name string; SEQUENCE OF KerberosString
  list = der_parse_sequence(seq:seq[1], list: TRUE);
  if(isnull(list)) return NULL; 
  
  # process each component in the name 
  fname = NULL;
  for(i = 0; i < list[0]; i++)
  {
    comp = der_parse_data(tag:0x1b, data: list[i + 1]);
    if(isnull(comp))  return NULL;
    if(concat)
    {
      if(i) fname += '/';
      fname += comp;
    }
    else
    {
      comp_list[i] = comp;
    }
  }

  ret[0] = type;
  if(concat)  ret[1] = fname;
  else        ret[1] = comp_list;

  return ret;
}

##
# Converts user password to key
#
# @param enc_type encryption type
# @param password user password
# @param salt salt used to derive key
# @param s2kparams additional parameters used to derive key
# @return key or NULL on error
# @remark salt and s2kparams are only applicable to enc_types that require them
#
##
function krb_string_to_key(enc_type, password, salt, s2kparams)
{
  local_var i,keysize, pass;
  # rc4-hmac5
  if(enc_type == 23)
  { 
    pass = NULL; for(i = 0; i < strlen(password); i++) pass += password[i] + '\x00';
    return  rc4_hmac_string_to_key (string:pass);
  }
  # aes256-cts-hmac-sha1-96 
  else if (enc_type == 18)
     return krb_string_to_key_aes(password:password, salt:salt, iter:s2kparams, keysize:32);
  # aes128-cts-hmac-sha1-96
  else if(enc_type == 17)
     return krb_string_to_key_aes(password:password, salt:salt, iter:s2kparams, keysize:16);
  # des-cbc-md5
  else if (enc_type == 3)
     return des_cbc_string_to_key (_string:password, salt:salt);

  # Unsupported encryptions types
  return NULL;
}

##
# Gets a service ticket for principal 'host/<host>'
#
# @param login user login
# @param password user password
# @param realm kerberos realm 
# @param sname target service principal; can be in form 'component1/component2 ...' or a list of components 
# @return a session credential or NULL on error 
#   ret[0] = der-encoded service ticket
#   ret[1] = session key to be used with the ticket
#   ret[2] = der-encoded client realm   
#   ret[3] = der-encoded client name   
#   ret[4] = encryption type the session key is meant to be used with   
#   ret[5] = ticket expiration time   
#   ret[6] = der-encoded padata; can be NULL   
#
##
function krb_get_ticket(login, password, realm, sname, type)
{
  local_var enc_type, i, kdc_tcp, req, resp, session, soc2, supported, ret;
  local_var key, request, padata, pa_enc, pa_pac, salt, s2kparams;
  local_var kdc_enc, kdc_enctypes, match, tgs_session, reqbytes;


  #
  #  AS exchange
  #  
  # Start AS-REQ without preauth padata
  request = der_encode_request (req:raw_string (0xFF));
  pa_pac = der_encode_padata (type:128, value:request);
  padata =  pa_pac; 
  req = der_encode_asreq (principal:login, realm:realm,padata: padata);
  session = NULL;
  i = 0;
  while(! session)
  {
    # Too many AS-REQ send
    if (i++ > 10) return NULL;

    # Open connection with KDC
    soc2 = get_kdc_socket(type:type);
    if (! soc2) return NULL;
   
    # Send AS-REQ 
    if(!req) return NULL;
    kdc_tcp = get_kb_item("Kerberos/" + type + "/kdc_use_tcp");
    if(kdc_tcp) reqbytes = raw_dword(d:strlen(req) & 0x7fffffff, be: TRUE) + req;
    else reqbytes = req;

    send (socket:soc2, data:reqbytes);
 
		# Check response, (48 * 1024), Microsoft recommends 48,000 and used to recommend 65536 thus 48K is used.
    resp = recv (socket:soc2, length:49152);
    close (soc2);
    if (!resp) return NULL;
    if(kdc_tcp) resp = substr(resp, 4);
    session = der_decode_asrep(password:password, data:resp);

    # Got AS-REP
    if(session) break; 
 
    # Got KRB-ERROR 
    ret = der_decode_krberror(data: resp); 
    if(isnull(ret)) return NULL;

    # Handle KDC_ERR_PREAUTH_REQUIRED
    if (ret[0] == 25)
    {
      # Check if enc-timestamp pre-auth is supported
      if (isnull(krb_padata_lookup(data: ret[2], type: 2)))
        return NULL; 
     
      # If so, get KDC supported enctypes 
      kdc_enctypes = krb_get_enctypes_from_padata(data:ret[2]);
      if(isnull(kdc_enctypes)) return NULL;

      # Find a KDC enctype we also support
      match = FALSE; 
      foreach kdc_enc(kdc_enctypes)
      {
        if(supported_encryption_type(type: kdc_enc[0]))
        {
          match = TRUE;
          break;
        }
      } 

      # No matching enctype
      if(! match) return NULL;
     
      # Get enctype, and the optional salt and s2kparams associated with the enctype
      enc_type  = kdc_enc[0];
      salt      = kdc_enc[1];
      s2kparams = kdc_enc[2];
     
      # Convert password to key 
      if(isnull(salt)) salt = realm + login; # no salt = default salt
      key = krb_string_to_key(enc_type: enc_type, password: password, salt: salt,  s2kparams: s2kparams);

      # Encrypt timestamp
      pa_enc = der_encode_paenc (time:kerberostime());
      pa_enc = der_encode_crypt (data:pa_enc, key:key, type:1, enc_type:enc_type);
      pa_enc = der_encode_padata (type:2, value:pa_enc);

      # Send AS-REQ with pre-auth
      padata =  pa_enc + pa_pac; 
      req = der_encode_asreq (principal:login, realm:realm,padata: padata);
      continue;
    }
    # Handle KRB_ERR_RESPONSE_TOO_BIG; retry with TCP
    else if (ret[0] ==  52)
    {
      if(! kdc_tcp)
      {
        kdc_tcp = TRUE;
        replace_kb_item(name:"Kerberos/" + type + "/kdc_use_tcp", value: TRUE);
        continue; 
      }
    }
    # Unhandled error
    else return NULL;
  }
     
  if(isnull(session)) return NULL;

  #
  # TGS exchange
  #
  tgs_session = NULL;
  req = der_encode_tgsreq (session:session,name:sname);
  i = 0;
  while(! tgs_session)
  {
    # Too many TGS-REQ send
    if (i++ > 10) return NULL;

    # Connect to KDC
    soc2 = get_kdc_socket(type:type);
    if (! soc2) return NULL;
   
    # Send TGS-REQ 
    if(! req) return NULL;

    if(kdc_tcp) reqbytes = raw_dword(d:strlen(req) & 0x7fffffff, be: TRUE) + req;
    else reqbytes = req;

    send (socket:soc2, data:reqbytes);

    # Check response, (48 * 1024), Microsoft recommends 48,000 and used to recommend 65536 thus 48K is used.
    resp = recv (socket:soc2, length:49152);
    close (soc2);
    if (!resp) return NULL;
    if(kdc_tcp) resp = substr(resp, 4); 
    tgs_session = der_decode_tgsrep(session:session, data:resp);

    # Got TGS-REP
    if(tgs_session) break;

    # Got KBR-ERROR
    ret = der_decode_krberror(data: resp); 
    if(isnull(ret)) return NULL;

    # Handle KRB_ERR_RESPONSE_TOO_BIG/KRB_ERR_FIELD_TOOLONG
    # Also seen MS-Kerberos returns KRB_ERR_FIELD_TOOLONG on if TGS-REQ UDP is larger than MaxDatagramReplySize
    if(ret[0] == 52 || ret[0] == 61)
    {
      if(! kdc_tcp)
      {
        kdc_tcp = TRUE;
        replace_kb_item(name:"Kerberos/" + type + "/kdc_use_tcp", value: TRUE);
        continue;
      }
    } 
    # Unhandled error
    else return NULL;
  } 

  return tgs_session;
}

# minimizing warnings on scanners < 6.x
global_var _SKTEX_KDC, _SKTEX_TCP, _SKTEX_UDP, _SKTEX_SSH, _SKTEX_SMB;

_SKTEX_KDC = 0x01;
_SKTEX_TCP = 0x04;
_SKTEX_UDP = 0x08;
_SKTEX_SSH = 0x20;
_SKTEX_SMB = 0x40;

function get_kdc_socket(type)
{
  local_var valid_types, socket, flags, use_tcp;
  valid_types = make_array(
    "SSH", _SKTEX_KDC | _SKTEX_SSH,
    "SMB", _SKTEX_KDC | _SKTEX_SMB
  );

  if (!defined_func("open_sock_ex") || isnull(type) || !valid_types[type])
    socket = open_sock_kdc();
  else
  {
    use_tcp = get_kb_item("Kerberos/" + type + "/kdc_use_tcp");
    if (use_tcp)
      flags = _SKTEX_TCP;
    else
      flags = _SKTEX_UDP;

    flags = flags | valid_types[type];
    socket = open_sock_ex(flags:flags);
  }

  return socket;
}

