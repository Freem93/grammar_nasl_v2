#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# $Revision: 1.2 $
# 

###############################################################
# ISAKMP definitions (RFC 2408)                               #
###############################################################

#
# Payload Types
#
IKE1_PAYLOAD_NONE           = 0;
IKE1_PAYLOAD_SA             = 1;
IKE1_PAYLOAD_PROPOSAL       = 2;
IKE1_PAYLOAD_TRANSFORM      = 3;
IKE1_PAYLOAD_KE             = 4;
IKE1_PAYLOAD_ID             = 5;
IKE1_PAYLOAD_CERT           = 6;
IKE1_PAYLOAD_CERT_REQ       = 7;
IKE1_PAYLOAD_HASH           = 8;
IKE1_PAYLOAD_SIG            = 9;
IKE1_PAYLOAD_NONCE          = 10;
IKE1_PAYLOAD_NOTIFY         = 11;   
IKE1_PAYLOAD_DELETE         = 12;
IKE1_PAYLOAD_VID            = 13;

#
# Exchange Types
#
ISAKMP_EXCH_NONE                = 0;
ISAKMP_EXCH_BASE                = 1; 
ISAKMP_EXCH_IDENTITY_PROTECTION = 2; # Main Mode in IKE
ISAKMP_EXCH_AUTH_ONLY           = 3;
ISAKMP_EXCH_AGGRESSIVE          = 4; 
ISAKMP_EXCH_INFORMATIONAL       = 5;

IKE1_MAIN_MODE                  = ISAKMP_EXCH_IDENTITY_PROTECTION;
IKE1_AGGRESSIVE_MODE            = ISAKMP_EXCH_AGGRESSIVE;

#
# Flags (1-byte)
#
IKE1_HDR_FLAGS_ENCRYPTION     = 0x01;
IKE1_FLAGS_COMMIT             = 0x02;
IKE1_FLAGS_AUTH               = 0x04;


#
# Notification types in Notification Payload
#
IKN1_INVALID_PAYLOAD_TYPE    = 1;
IKN1_DOI_NOT_SUPPORTED       = 2;
IKN1_SITUATION_NOT_SUPPORTED = 3;
IKN1_INVALID_COOKIE          = 4;
IKN1_INVALID_MAJOR_VER       = 5;
IKN1_INVALID_MINOR_VER       = 6;
IKN1_INVALID_EXCH_TYPE       = 7;
IKN1_INVALID_FLAGS           = 8;
IKN1_INVALID_MSG_ID          = 9;
IKN1_INVALID_PROTO_ID        = 10;
IKN1_INVALID_SPI             = 11;
IKN1_INVALID_XFORM_ID        = 12;
IKN1_ATTR_NOT_SUPPORTED      = 13;
IKN1_NO_PROPOSAL_CHOSEN      = 14;
IKN1_BAD_PROPOSAL_SYNTAX     = 15;
IKN1_PAYLOAD_MALFORMED       = 16;
IKN1_INVALID_KEY_INFO        = 17;
IKN1_INVALID_ID_INFO         = 18;
IKN1_INVALID_CERT_ENCODING   = 19;
IKN1_INVALID_CERT            = 20;
IKN1_CERT_TYPE_UNSUPPORTED   = 21;
IKN1_INVALID_CA              = 22;
IKN1_INVALID_HASH_INFO       = 23;
IKN1_AUTH_FAILED             = 24;
IKN1_INVALID_SIG             = 25;
IKN1_ADDRESS_NOTIFY          = 26;
IKN1_SA_LIFETIME_NOTIFY      = 27;
IKN1_CERT_UNAVAILABLE        = 28;
IKN1_UNSUPPORTED_EXCH_TYPE   = 29;
IKN1_UNEQUAL_PAYLOAD_LEN     = 30;
# 31 - 8191 (reserved)
# 8192 - 16383 (private use / DOI-specific)
IKN1_CONNECTED               = 16384;
# 16385 - 24575 (reserved)
# 24576 - 32767 ( DOI-specific)
# 32768 - 40959 (private use)
# 40960 - 65535 (reserved)


#
# ISAKMP Identification Type Values used in Phase 1
# rfc 2048, section A.4
# used when DOI is DOI_ISAKMP
#
DOI_ISAKMP_ID_IPV4_ADDR            = 0;
DOI_ISAKMP_ID_IPV4_ADDR_SUBNET     = 1;
DOI_ISAKMP_ID_IPV6_ADDR            = 2;
DOI_ISAKMP_ID_IPV6_ADDR_SUBNET     = 3;


#
# Domain of Interpretation
#
DOI_ISAKMP  = 0;
DOI_IPSEC   = 1;



###############################################################
# Definitions from RFC 2407  (IPSec DOI for ISAKMP)           #
###############################################################

# situation
SIT_IDENTITY        = 0x01;
SIT_SECRECY         = 0x02;
SIT_INTEGRITY       = 0x04;
     
#
# protocol id for the current negotiation
#
PROTO_ISAKMP        = 1;
PROTO_IPSEC_AH      = 2;
PROTO_IPSEC_ESP     = 3;
PROTO_IPCOMP        = 4;

#
# IPSEC ISAKMP Transform Identifiers (used in phase I)
# rfc 2407, section 4.4.2
KEY_IKE             = 1;


#
# IPSEC AH Transform Identifiers 
#
AH_MD5    = 2;
AH_SHA    = 3;
AH_DES    = 4;

#
# IPSEC ESP Transform Identifiers
#
ESP_DES_IV64  = 1;
ESP_DES       = 2;
ESP_3DES      = 3;
ESP_RC5       = 4;
ESP_IDEA      = 5;
ESP_CAST      = 6;
ESP_BLOWFISH  = 7;
ESP_3IDEA     = 8;
ESP_DES_IV32  = 9;
ESP_RC4       = 10;
ESP_NULL      = 11;


#
# IPSEC IPCOMP Transform Identifiers
#
IPCOMP_OUI      = 1;
IPCOMP_DEFLATE  = 2;
IPCOMP_LZS      = 3;


#
# IPSEC Security Association Attributes (phase II)
#
# RFC 2407, section 4.5
IPSEC_SA_ATTR_LIFE_TYPE         = 1;
IPSEC_SA_ATTR_LIFE_DURATION     = 2;
IPSEC_SA_ATTR_GROUP             = 3;
IPSEC_SA_ATTR_ENCAP_MODE        = 4;
IPSEC_SA_ATTR_AUTH_ALG          = 5;
IPSEC_SA_ATTR_KEY_LENGTH        = 6;
IPSEC_SA_ATTR_KEY_ROUNDS        = 7;
IPSEC_SA_ATTR_COMP_DICT_SIZE    = 8;
IPSEC_SA_ATTR_PRIVATE_ALG       = 9;

#
# Encapsulation Mode
#
IPSEC_ENCAP_TUNNEL          = 1;
IPSEC_ENCAP_TRANSPORT       = 2;

#
# Authentication Algorithm
#
IPSEC_AUTH_HMAC_MD5         = 1;
IPSEC_AUTH_HMAC_SHA1        = 2;
IPSEC_AUTH_DES_MAC          = 3;
ISPEC_AUTH_KPDK             = 4;


#
# Identification Type Values 
# used when DOI is DOI_IPSEC
#
IPSEC_ID_IPV4_ADDR          = 1;
IPSEC_ID_FQDN               = 2;
IPSEC_ID_USER_FQDN          = 3;
IPSEC_ID_IPV4_ADDR_SUBNET   = 4;
IPSEC_ID_IPV6_ADDR          = 5;
IPSEC_ID_IPV6_ADDR_SUBNET   = 6;
IPSEC_ID_IPV4_ADDR_RANGE    = 7;
IPSEC_ID_IPV6_ADDR_RANGE    = 8;
IPSEC_ID_DER_ASN1_DN        = 9;
IPSEC_ID_DER_ASN1_GN        = 10;
IPSEC_ID_KEY_ID             = 11;

#
# IPSEC Notify Message Types
#
IPSEC_IKN_RESPONDER_LIFETIME  = 24576;
IPSEC_IKN_REPLAY_STATUS       = 24577;
IPSEC_IKN_INITIAL_CONTACT     = 24578;          



###############################################################
# Definitions from RFC 2409  (IKE v1)                         #
###############################################################

#
# Phase I Attributes
#
IKE1_ATTR_ENC                 = 1;
IKE1_ATTR_HASH                = 2;
IKE1_ATTR_AUTH                = 3;
IKE1_ATTR_GROUP_DESCR         = 4; 
IKE1_ATTR_GROUP_TYPE          = 5;
IKE1_ATTR_GROUP_PRIME_POLY    = 6;
IKE1_ATTR_GROUP_GEN_ONE       = 7;
IKE1_ATTR_GROUP_GEN_TWO       = 8;
IKE1_ATTR_GROUP_CURVE_A       = 9;
IKE1_ATTR_GROUP_CURVE_B       = 10;
IKE1_ATTR_LIFE_TYPE           = 11;
IKE1_ATTR_LIFE_DURATION       = 12;
IKE1_ATTR_PRF                 = 13;
IKE1_ATTR_KEY_LEN             = 14;
IKE1_ATTR_FIELD_SIZE          = 15;
IKE1_ATTR_GROUP_ORDER         = 16;


#
# Encryption algorithms
#
IKE1_ENC_DES_CBC          = 1;
IKE1_ENC_IDEA_CBC         = 2;
IKE1_ENC_BLOWFISH_CBC     = 3;
IKE1_ENC_RC5_CBC          = 4;
IKE1_ENC_3DES_CBC         = 5;
IKE1_ENC_CAST_CBC         = 6;
# The following are not in rfc 2409, but in http://www.iana.org/assignments/ipsec-registry
IKE1_ENC_AES_CBC          = 7; 
IKE1_ENC_CAMELLIA_CBC     = 8;


#
# Hash algorithms
#
IKE1_HASH_MD5       = 1;
IKE1_HASH_SHA1      = 2;
IKE1_HASH_TIGER     = 3;
# The following are not in rfc 2409, but in http://www.iana.org/assignments/ipsec-registry
IKE1_HASH_SHA2_256  = 4;
IKE1_HASH_SHA2_384  = 5;
IKE1_HASH_SHA2_512  = 6;



#
# Authentication methods
#
IKE1_AUTH_PSK          = 1;
IKE1_AUTH_SIG_DSS      = 2;
IKE1_AUTH_SIG_RSA      = 3;
IKE1_AUTH_ENC_RSA      = 4;
IKE1_AUTH_ENC_RSA_REV  = 5;
# more values in http://www.iana.org/assignments/ipsec-registry




#
# Group types
#
IKE1_GROUP_TYPE_MODP   = 1;
IKE1_GROUP_TYPE_ECP    = 2;
IKE1_GROUP_TYPE_EC2N   = 3;

#
# Life types
#
IKE1_LIFE_TYPE_SECS    = 1;
IKE1_LIFE_TYPE_KBS     = 2;
    

##
# Creates a IKEv1 header
#
# @param icookie [data] Initiator Cookie
# @param rcookie [data] Responder Cookie
# @param payload [int]  Type of the first payload following the header
# @param mj_ver [int]   IKE major version
# @param mn_ver [int]   IKE minor version
# @param exch [int]     Exchange type
# @param flags [int]    Header flags
# @param msgid [int]    Message ID
# @param len [int]      Total length of the IKE PDU
# 
# @return [data] formatted IKEv1 header
# @remark 
#   - For more information, see RFC 2408, section 3.1 
#
##    
function ike1_hdr(icookie, rcookie, payload, exch, flags, msgid, len)
{
  return ike_hdr(ispi:icookie, rspi:rcookie, payload:payload, exch:exch, mj_ver:1, mn_ver: 0, flags:flags, msgid:msgid, len:len);
}

##
# Creates a IKEv1 payload header
#
# @param next [int] Type of next payload
# @param len [int]  Total length of the payload, including the payload header
# @return [data]    Formatted payload header
# @remark
#   - For more information, see RFC 2408, section 3.2
#
##
function ike1_payload_hdr(next, len)
{
  local_var hdr;
  
  hdr = mkbyte(next) + raw_string(0) + mkword(len); # payload length includes len of hdr
  return hdr;
}

##
# Creates a IKEv1 payload 
#
# @param next [int]   Type of next payload
# @param data [data]  Raw data of the payload
# @return [data]      Formatted payload 
#
##
function ike1_payload(next, data)
{
  local_var hdr, len;
  
  len = strlen(data) + 4; # 4-byte payload header
  
  hdr = ike1_payload_hdr(next:next,len:len);
  
  return (hdr + data);
}
##
# Creates a IKEv1 Security Association (SA) payload 
#
# @param next [int]       Type of next payload
# @param doi [int]        Domain of Interpretation (DOI); i.e., DOI_ISAKMP, DOI_IPSEC
# @param situation [int]  DOI-specific situation under which the negotiation is taking place
# @param proposals [data] One or more proposal payloads
# @return [data]          Formatted SA payload 
# @remark
#   - If doi is DOI_ISAKMP, phase 1 SA can be used by any protocol in phase 2.
#     If doi is DOI_IPSEC, phase 1 SA can only be used by IPSEC protocols (i.e., ESP, AH)
# 
##
function ike1_payload_sa(next, doi, situation, proposals)
{
  local_var data;
  data = mkdword(doi) + mkdword(situation) + proposals;
  return ike1_payload(next:next,data:data);
}

##
# Creates a IKEv1 Proposal payload 
#
# @param next [int]       Type of next payload
# @param num [int]        Proposal number
# @param proto [int]      Protocol ID for the current negotiation
# @param spi [data]       Security Parameter Index (SPI)
# @param xforms [list]    A list of formatted transform payloads
# @return [data]          Formatted proposal payload 
# 
##
function ike1_payload_prop(next, num, proto, spi, xforms)
{
  local_var data, t, xf;
  
  xf = NULL; foreach t (xforms) xf += t;
  
  data =  mkbyte(num) +
          mkbyte(proto) +
          mkbyte(strlen(spi)) +
          mkbyte(max_index(xforms)) +
          spi +
          xf;
  return ike1_payload(next:next,data:data);
}

##
# Creates a IKEv1 Transform payload 
#
# @param next [int]       Type of next payload
# @param num [int]        Transform number
# @param id [int]         Transform ID
# @param attrs [data]     Formatted SA attributes
# @return [data]          Formatted proposal payload 
# 
##
function ike1_payload_xform(next, num, id, attrs)
{
  local_var data;
  
  data =  mkbyte(num) +
          mkbyte(id) +
          mkword(0) +
          attrs;
  return ike1_payload(next:next,data:data);
}

##
# Creates a IKEv1 Identification payload 
#
# @param next [int]   Type of next payload
# @param type [int]   Identification type
# @param proto[int]   Value specifying an associated IP protocol; 0 means the field should be ignored
# @param port [int]   Value specifying an associated port; 0 means the field should be ignored
# @param data [data]  Identification data
# @return [data]      Formatted identification payload 
# @remark
#   - For more information, see RFC 2407, section 4.6.2
##
function ike1_payload_id(next, type, proto, port, data)
{
  data =  mkbyte(type) + mkbyte(proto) + mkword(port) + data;
  
  return ike1_payload(next:next,data:data);
}

##
# Creates a IKEv1 Delete payload 
#
# @param next [int]     Type of next payload
# @param doi [int]      Domain of Interpretation
# @param proto[int]     Protocol ID with which the SA is associated; i.e., PROTO_ISAKMP, PROTO_ESP
# @param spi_size[int]  Size of the SPI; 16 for ISAKMP SPI, 4 for ESP SPI
# @param spi_list[data] SPI(es) to delete
# @return [data]        Formatted delete payload 
# @remark
#   - For more information, see RFC 2408, section 3.15
##
function ike1_payload_delete(next, doi, proto, spi_size, spi_list)
{
  local_var data, spi, tmp;
  
  tmp = NULL; foreach spi (spi_list) tmp += spi;
   
  data =  mkdword(doi) +
          mkbyte(proto) +
          mkbyte(spi_size) +
          mkword(max_index(spi_list)) +
          tmp;
          
  return ike1_payload(next:next,data:data);
  
}




##
# Creates a Phase 1 Proposal with Transforms permutated with a list of
#   1) encryption algorithms
#   2) hash algorithms
#   3) authentication methods
#   4) DH groups
#
# @param enc_list [list]    A list of encryption algorithms (including key length) to be included in the proposal
# @param hash_list [list]   A list of hash algorithms to be included in the proposal
# @param group_list [list]  A list of DH groups to be included in the proposal
# @param auth_list [list]   A list of authentication methods to be included in the proposal
# @return [data]            Formatted proposal payload
#
# @remark - RFC 2409, section 4 says the above attributes are mandatory and MUST be negotiated
#  
##
function ike1_phase1_proposal(enc_list, hash_list, auth_list, group_list)
{
  local_var auth, enc, group, hash, i, id, j, keylen, xforms;
  local_var attrs, attr_enc, attr_hash, attr_auth, attr_group, attr_keylen, proposal, xform;
  
  if(max_index(enc_list)  == 0) return NULL;
  if(max_index(hash_list) == 0) return NULL;
  if(max_index(auth_list) == 0) return NULL;
  if(max_index(group_list)== 0) return NULL;
  
  
  i = 0; 
  xforms = NULL;
  for (j = 0; j < max_index(enc_list); j++)
  {
    enc = enc_list[j];
    id      = enc[0];
    keylen  = enc[1];
    
    attr_enc = ike_attr(type: IKE1_ATTR_ENC, value: id);
    if(keylen) attr_keylen = ike_attr(type: IKE1_ATTR_KEY_LEN, value: keylen);
    else       attr_keylen = NULL;
    foreach hash (hash_list)
    {
      attr_hash = ike_attr(type: IKE1_ATTR_HASH, value: hash);
      foreach auth (auth_list)
      {
        attr_auth = ike_attr(type: IKE1_ATTR_AUTH, value: auth);
        foreach group (group_list)
        {
          attr_group = ike_attr(type: IKE1_ATTR_GROUP_DESCR, value: group);
          
          attrs = attr_enc + attr_keylen + attr_hash + attr_auth + attr_group;
          
          # Last Transform
          if( j == max_index(enc_list) - 1 &&
             hash == hash_list[max_index(hash_list) - 1] &&
             auth == auth_list[max_index(auth_list) - 1] &&
             group== group_list[max_index(group_list) - 1]
            ) xforms[i++] = ike1_payload_xform(next:IKE1_PAYLOAD_NONE, num: i + 1, id: KEY_IKE, attrs: attrs);
         else xforms[i++] = ike1_payload_xform(next:IKE1_PAYLOAD_TRANSFORM, num: i + 1, id: KEY_IKE, attrs: attrs);
        }
      }
    }
  }
  
  if(isnull(xforms)) return NULL;
  
  return ike1_payload_prop(next: IKE1_PAYLOAD_NONE,
                             num: 1, # one proposal
                             proto: PROTO_ISAKMP,
                             spi: '',
                             xforms: xforms);
}

##
# Parses IKEv1 Notification payload data
#
# @anonparam [data]   Raw data of the Notification payload
# @return [array]     ret['doi'] [int]    - Domain of Interpretation 
#                     ret['proto'] [int]  - Protocol ID; 1 = IKE, 2 = ESP, 3 = AH
#                     ret['spi'] [data]   - SPI if any
#                     ret['type'] [int]   - Notification type
#                     ret['data'] [data]  - Notification data if any
#
# @remark
#   - This function returns NULL if it fails.
#   - For more details, see RFC 2408, section 3.14  
##
function ike1_parse_notify()
{
  local_var data, len, pos, ret, spi_size;

  data = _FCT_ANON_ARGS[0];
  len = strlen(data);

  # Sizes for doi, proto, spi_size, and notification type fields
  if(len < 4 + 1 + 1 + 2) return NULL;

  pos = 0;
  ret['doi']      = getdword(blob:data, pos:pos); pos += 4;
  ret['proto']    = getbyte(blob:data, pos:pos); pos += 1;
  spi_size        = getbyte(blob:data, pos:pos); pos += 1;
  ret['type']     = getword(blob:data, pos:pos); pos += 2;

  # Get SPI
  if(spi_size)
  {
    # Invalid spi_size
    if(pos + spi_size > len) return NULL;

    ret['spi'] = substr(data, pos, pos + spi_size -1 );

    pos += spi_size;
  }

  # Get notification data if any
  if(pos < len)
  {
    ret['data'] = substr(data, pos);
  }

  return ret;
}

#
# Wrappers
#
function ike1_parse()
{
  local_var pdu;
  
  pdu = _FCT_ANON_ARGS[0];
  return ike_parse(pdu);
}
function ike1_pcap_sendrecv(data, filter, timeout)
{
  return ike_pcap_sendrecv(data:data, filter:filter, timeout:timeout);
}

function ike1_sendrecv(socket, data)
{
  return ike_sendrecv(socket: socket, data: data);
}

function ike1_attr(type, value)
{
  return ike_attr(type:type, value:value);
}

function ike1_cipher()
{
  local_var id, keylen;
  
  id      = _FCT_ANON_ARGS[0];
  keylen  = _FCT_ANON_ARGS[1];
  
  return ike_cipher(id, keylen);
 
}


