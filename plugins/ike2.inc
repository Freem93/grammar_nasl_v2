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

#
# Exchange Types
#
IKE2_EXCH_SA_INIT            = 34;
IKE2_EXCH_AUTH               = 35;
IKE2_EXCH_CREATE_CHILD_SA    = 36;
IKE2_EXCH_INFORMATIONAL      = 37;


#
# Flags in the IKE header
#
IKE2_FLAG_INITIATOR     = 0x08;
IKE2_FLAG_VERSION       = 0x10;
IKE2_FLAG_RESP          = 0x20;



#
# Payload types
#
IKE2_PAYLAOD_NONE       = 0;
IKE2_PAYLOAD_SA         = 33;
IKE2_PAYLOAD_KE         = 34;
IKE2_PAYLOAD_IDI        = 35;
IKE2_PAYLOAD_IDR        = 36;
IKE2_PAYLOAD_CERT       = 37;
IKE2_PAYLOAD_CERTREQ    = 38;
IKE2_PAYLOAD_AUTH       = 39;
IKE2_PAYLOAD_NONCE      = 40;
IKE2_PAYLOAD_NOTIFY     = 41;
IKE2_PAYLOAD_DELETE     = 42;
IKE2_PAYLOAD_VID        = 43;
IKE2_PAYLOAD_TSI        = 44;
IKE2_PAYLOAD_TSR        = 45;
IKE2_PAYLOAD_ENCRYPTED  = 46;
IKE2_PAYLOAD_CONFIG     = 47;
IKE2_PAYLOAD_EAP        = 48;




#
# Protocol IDs in Proposal payload
#
IKE2_PROTO_IKE        = 1;
IKE2_PROTO_AH         = 2;
IKE2_PROTO_ESP        = 3;


#
# Transform types in Transform payload
#
IKE2_XFORM_ENC          = 1;
IKE2_XFORM_PRF          = 2;
IKE2_XFORM_INTEG        = 3;
IKE2_XFORM_DH_GROUP     = 4;
IKE2_XFORM_ESN          = 5; # Extended Sequence Numbers

#
# Transform IDs for IKE2_XFORM_ENC
#
IKE2_ENC_DES_IV64     = 1;
IKE2_ENC_DES          = 2;
IKE2_ENC_3DES         = 3;
IKE2_ENC_RC5          = 4;
IKE2_ENC_IDEA         = 5;
IKE2_ENC_CAST         = 6;
IKE2_ENC_BLOWFISH     = 7;
IKE2_ENC_3IDEA        = 8;
IKE2_ENC_DES_IV32     = 9;
IKE2_ENC_NULL         = 11;
IKE2_ENC_AES_CBC      = 12;
IKE2_ENC_AES_CTR      = 13;

#
# Attributes type used in the Transform substructure
#
IKE2_ATTR_KEYLEN      = 14;


#
# Transform IDs for IKE2_XFORM_PRF
#
IKE2_PRF_HMAC_MD5     = 1;
IKE2_PRF_HMAC_SHA1    = 2;
IKE2_PRF_HMAC_TIGER   = 3;
IKE2_PRF_AES128_XCBC  = 4;

#
# Transform IDs for IKE2_XFORM_INTEG
#
IKE2_INTEG_HMAC_MD5_96   = 1;
IKE2_INTEG_HMAC_SHA1_96  = 2;
IKE2_INTEG_DES_MAC       = 3;
IKE2_INTEG_KPDK_MD5      = 4;
IKE2_INTEG_AES_XCBC_96   = 5;


#
# Notification types
#
# Error types
IKN2_UNSUPPORTED_CRITICAL_PAYLOAD   = 1;
IKN2_INVALID_IKE_SPI                = 2;
IKN2_INVALID_MAJOR_VERSION          = 3;
IKN2_INVALID_SYNTAX                 = 7;
IKN2_INVALID_MESSAGE_ID             = 9;
IKN2_INVALID_SPI                    = 11;
IKN2_NO_PROPOSAL_CHOSEN             = 14;
IKN2_INVALID_KE_PAYLOAD             = 17;
IKN2_AUTHENTICATION_FAILED          = 24;
IKN2_SINGLE_PAIR_REQUIRED           = 34;
IKN2_NO_ADDITIONAL_SAS              = 35;
IKN2_INTERNAL_ADDRESS_FAILURE       = 36;
IKN2_FAILED_CP_REQUIRED             = 37;
IKN2_TS_UNACCEPTABLE                = 38;
IKN2_INVALID_SELECTORS              = 39;
IKN2_TEMPORARY_FAILURE              = 43;
IKN2_CHILD_SA_NOT_FOUND             = 44;
# Status types
IKN2_INITIAL_CONTACT                = 16384;
IKN2_SET_WINDOW_SIZE                = 16385;
IKN2_ADDITIONAL_TS_POSSIBLE         = 16386;
IKN2_IPCOMP_SUPPORTED               = 16387;
IKN2_NAT_DETECTION_SOURCE_IP        = 16388;
IKN2_NAT_DETECTION_DESTINATION_IP   = 16389;
IKN2_COOKIE                         = 16390;
IKN2_USE_TRANSPORT_MODE             = 16391;
IKN2_HTTP_CERT_LOOKUP_SUPPORTED     = 16392;
IKN2_REKEY_SA                       = 16393;
IKN2_ESP_TFC_PADDING_NOT_SUPPORTED  = 16394;
IKN2_NON_FIRST_FRAGMENTS_ALSO       = 16395;


#
# Authentication methods
#
IKE2_AUTH_RSA_SIG       = 1;
IKE2_AUTH_SHARED_KEY    = 2;
IKE2_AUTH_DSS_SIG       = 3;

##
# Creates an IKEv2 header
#
# @param ispi [data]    Initiator SPI (known as Initiator Cookie in IKEv1)
# @param rspi [data]    Responder SPI (known as Responder Cookie in IKEv1)
# @param payload [int]  Type of the first payload following the header
# @param mj_ver [int]   IKE major version
# @param mn_ver [int]   IKE minor version
# @param exch [int]     Exchange type
# @param flags [int]    Header flags
# @param msgid [int]    Message ID
# @param len [int]      Total length of the IKE PDU
#
# @return [data] formatted IKEv2 header
# @remark see RFC 5996, section 3.1
#
##
function ike2_hdr(ispi, rspi, payload, exch, flags, msgid, len)
{
  return ike_hdr(ispi:ispi, rspi:rspi, payload:payload, exch:exch, mj_ver:2, mn_ver: 0, flags:flags, msgid:msgid, len:len);
}

##
# Creates an IKEv2 payload header
#
# @param next [int] Type of next payload
# @param c [int]    Critical payload bit; default = 0
# @param len [int]  Total length of the payload, including the payload header
# @return [data]    Formatted payload header
# @remark
#   - For more information, see RFC 5996, section 3.2
#
##
function ike2_payload_hdr(next,c,len)
{
  local_var hdr;

  if(isnull(c)) c = 0;

  hdr = mkbyte(next) +
        raw_string(((c & 0x1) << 7) & 0xff) +
        mkword(len); # payload length includes len of payload hdr
  return hdr;
}

##
# Creates an IKEv2 payload
#
# @param next [int]   Type of next payload
# @param c [int]      Critical payload bit; default = 0
# @param data [data]  Raw data of the payload
# @return [data]      Formatted payload
#
##
function ike2_payload(next, c, data)
{
  local_var hdr, len;

  if(isnull(c)) c = 0;

  len = strlen(data) + 4; # 4-byte payload header

  hdr = ike2_payload_hdr(next:next, c:c, len:len);

  return (hdr + data);
}

##
# Creates an IKEv2 Security Association (SA) payload
#
# @param next [int]       Type of next payload
# @param c [int]          Critical payload bit; default = 0
# @param proposals [data] One or more proposal substructures
# @return [data]          Formatted SA payload
# @remark
#   For more details, see RFC 5996, section 3.3
##
function ike2_payload_sa(next,c, proposals)
{
  return ike2_payload(next:next,c:c, data:proposals);
}


##
# Creates an IKEv2 Authentication (AUTH) payload
#
# @param next [int]       Type of next payload
# @param c [int]          Critical payload bit; default = 0
# @param method [int]     Authentication method
# @param data [data]      Authentication data
# @return [data]          Formatted AUTH payload
# @remark
#   For more details, see RFC 5996, section 3.8
##
function ike2_payload_auth(next, c, method, data)
{
  data = mkbyte(method) + mkword(0) + data;
  return ike2_payload(next:next,c:c, data:data);
}


##
# Creates an IKEv2 Proposal Substructure
#
# @param next [int]       0 (last) or 2 (next proposal)
# @param num [int]        Proposal number
# @param proto [int]      Protocol ID
# @param spi [data]       SPI
# @param xforms [list]    A list of formatted transform substructure(s)
# @return [data]          A formatted proposal substructure
# @remark
#   For more details, see RFC 5996, section 3.3.1
##
function ike2_proposal(next, num, proto, spi, xforms)
{
  local_var data, t, xf;

  xf = NULL; foreach t (xforms) xf += t;

  data =  mkbyte(num) +
          mkbyte(proto) +
          mkbyte(strlen(spi)) +
          mkbyte(max_index(xforms)) +
          spi+
          xf;
  return ike2_payload(next:next, data:data);

}

##
# Creates an IKEv2 Transform Substructure
#
# @param next [int]       0 (last) or 3 (next proposal)
# @param type [int]       Transform type
# @param id [int]         Transform ID
# @param attrs [data]     Transform attributes
# @return [data]          A formatted transform substructure
# @remark
#   For more details, see RFC 5996, section 3.3.2
##
function ike2_xform(next, type, id, attrs)
{
  local_var data;

  data =  mkbyte(type) +
          mkbyte(0) +
          mkword(id) +
          attrs;
  return ike2_payload(next:next,data:data);
}

##
# Creates an IKEv2 Key Exchange (KE) payload
#
# @param next [int]       Type of next payload
# @param c [int]          Critical payload bit; default = 0
# @param group[int]       DH group number
# @param data [data]      Key exchange data
# @return [data]          Formatted KE payload
# @remark
#   For more details, see RFC 5996, section 3.4
##
function ike2_payload_ke(next,c, group, data)
{
  data = mkword(group) + mkword(0) + data;
  return ike2_payload(next:next,c:c, data:data);
}

##
# Parses raw_data of an IKEv2 Notification payload
#
# @anonparam [data]   Raw data of the Notification payload
# @return [array]     ret['proto'] [int]  - Protocol ID; 1 = IKE, 2 = ESP, 3 = AH
#                     ret['spi'] [data]   - SPI
#                     ret['type'] [int]   - Notification type
#                     ret['data'] [data]  - Notification data
#
# @remark
#   - This function returns NULL if it fails.
#   - For more details, see RFC 5996, section 3.10
##
function ike2_parse_notify()
{
  local_var data, len, pos, ret, spi_size;

  data = _FCT_ANON_ARGS[0];
  len = strlen(data);

  # Sizes for proto, spi_size, and notification type fields
  if(len < 1 + 1 + 2) return NULL;

  pos = 0;
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

  if(pos < len)
  {
    # Get Notification data
    ret['data'] = substr(data, pos);
  }
  else if(pos > len)
  {
    return NULL;
  }
  return ret;

}


##
# Creates an IKEv2 Proposal for PROTO_IKE
#
# @param enc_list [list]    A list of encryption algorithms (including key length) to be included in the proposal
# @param integ_list [list]  A list of integrity algorithms to be included in the proposal
# @param group_list [list]  A list of DH groups to be included in the proposal
# @param prf_list [list]    A list of Pseudo Random Functions to be included in the proposal
# @param next [int]         Indicates whether another proposal follows this one; 0 = NONE, 2 = MORE, default = NONE
# @param num [int]          Proposal number; default = 1
# @return [data]            Formatted proposal with various transforms
#
# @remark
#   - if enc_list contains all combine-mode ciphers, integ_list is not needed.
#   - RFC 5996, section 2.7 says:
#       Each IPsec protocol proposal contains one or more transforms.  Each
#       transform contains a Transform Type.  The accepted cryptographic
#       suite MUST contain exactly one transform of each type included in the
#       proposal.
#
##
function ike2_proposal_ike(enc_list, integ_list, group_list, prf_list, next, num)
{
  local_var attrs, enc, group, i, id, integ, keylen, prop, prf, xforms;


  xforms = NULL;
  i = 0;

  # Encryption algorithms
  foreach enc (enc_list)
  {
    id = enc[0];
    keylen = enc[1];

    if(keylen) attrs = ike_attr(type: IKE2_ATTR_KEYLEN, value: keylen);
    else       attrs = NULL;

    xforms[i++] = ike2_xform(next:3, type: IKE2_XFORM_ENC, id:id, attrs: attrs);
  }

  # Integrity algorithms
  foreach integ (integ_list)
  {
    xforms[i++] = ike2_xform(next:3, type: IKE2_XFORM_INTEG, id:integ, attrs: NULL);
  }

  # DH groups
  foreach group (group_list)
  {
    xforms[i++] = ike2_xform(next:3, type: IKE2_XFORM_DH_GROUP, id:group, attrs: NULL);
  }

  # PRF
  foreach prf (prf_list)
  {
    if(prf == prf_list[max_index(prf_list) -1])
      xforms[i++] = ike2_xform(next:0, type: IKE2_XFORM_PRF, id:prf, attrs: NULL);
    else
      xforms[i++] = ike2_xform(next:3, type: IKE2_XFORM_PRF, id:prf, attrs: NULL);
  }

  if(isnull(xforms)) return NULL;

  if(isnull(next)) next = 0; # no more proposal to follow this proposal
  if(isnull(num))  num  = 1; # first proposal

  return ike2_proposal(next: next, num:num, proto:IKE2_PROTO_IKE, spi:'', xforms: xforms);

}

##
# Performs an IKEv2 SA_INIT exchange
#
# @param enc_list [list]    A list of encryption algorithms (including key length) to be included in the proposal
# @param integ_list [list]  A list of integrity algorithms to be included in the proposal
# @param group_list [list]  A list of DH groups to be included in the proposal
# @param prf_list [list]    A list of Pseudo Random Functions to be included in the proposal
# @param ke_group [int]     DH group number to be used in the KE payload
# @param ispi [data]        Initiator SPI
# @return [array]           A IKE status object;
#                           STATUS_SUCCESS - Remote IKEv2 daemon returns a SA payload, status['info'] contains the parsed PDU.
#                           STATUS_FAILURE - IKEv2 daemon is not listening on remote host
#                           STATUS_FAILURE_UNEXPECTED - Parsing errors etc; status['info'] has more details.
#                           IKN2_XXX       - Notification type/code sent by remote IKEv2 daemon; status['info'] contains the notification data.
#
#
##
function ike2_sa_init(enc_list, integ_list, group_list, prf_list, ke_group, ispi)
{
  local_var dh_x, hdr, ke, nonce, notify, payloads, pdu, prop, res, ret, sa;


  #
  # Check params
  #
  # ke_group MUST be one in group_list
  if(! item_in_list(list: group_list, item: ke_group))
    return ike_status(STATUS_FAILURE_UNEXPECTED, 'Invalid DH group specification.');


  prop = ike2_proposal_ike(enc_list: enc_list, integ_list: integ_list, group_list:group_list,
                         prf_list:prf_list);

  if(isnull(prop)) return ike_status(STATUS_FAILURE_UNEXPECTED, 'Failed to create an IKE proposal.');

  #
  # SA payload
  #
  sa = ike2_payload_sa(next:IKE2_PAYLOAD_KE, proposals:prop);
  if(isnull(sa)) return ike_status(STATUS_FAILURE_UNEXPECTED, 'Failed to create an SA payload.');

  #
  # Key Exchange Payload
  #
  # Compute g^x mod p.
  dh_x = bn_mod_exp(IKE_DH_GENERATOR_2, rand_str(length:16), IKE_DH_GROUP[ke_group]);
  ke = ike2_payload_ke(next:IKE2_PAYLOAD_NONCE, group:ke_group, data:dh_x);
  if(isnull(ke)) return ike_status(STATUS_FAILURE_UNEXPECTED, 'Failed to create a KE payload.');

  #
  # Nonce Payload
  #
  nonce = ike2_payload(next: 0, data:rand_str(length:32));

  payloads = sa + ke + nonce;

  hdr = ike2_hdr( ispi: ispi,
                  rspi: crap(data:'\x00', length:8),
                  payload: IKE2_PAYLOAD_SA,
                  exch: IKE2_EXCH_SA_INIT,
                  flags: IKE2_FLAG_INITIATOR,
                  msgid: 0,
                  len:IKE_HDR_SIZE + strlen(payloads));

  pdu = hdr + payloads;
  res = ike2_pcap_sendrecv(data:pdu);
  if(isnull(res)) return ike_status(STATUS_FAILURE,'No response from UDP port '+IKE_PORT+' to an IKE_SA_INIT message.');

  # Parse the response
  ret = ike2_parse(res);
  if(isnull(ret)) return ike_status(STATUS_FAILURE_UNEXPECTED, 'Received an invalid IKEv2 packet from remote UDP port '+IKE_PORT+'.');

  # Double check
  hdr       = ret['hdr'];
  payloads  = ret['payloads'];

  if(isnull(hdr))       return ike_status(STATUS_FAILURE_UNEXPECTED, 'Failed to get IKEv2 header in the response.');
  if(isnull(payloads))  return ike_status(STATUS_FAILURE_UNEXPECTED, 'Failed to get any IKEv2 payload in the response.');

  #
  # Check to see if the response is an SA_INIT response or a notification
  #

  # Got a notification
  if(hdr['np'] == IKE2_PAYLOAD_NOTIFY)
  {
    # First payload is the NOTIFY payload
    notify = payloads[0];
    notify = ike2_parse_notify(notify['raw_data']);

    if(isnull(notify) || isnull(notify['type']))
      return ike_status(STATUS_FAILURE_UNEXPECTED, 'Failed to parse IKEv2 Notification payload in the response.');
    #
    # return IKN2_XXX as status code, along with notification data
    #
    return ike_status(notify['type'], notify['data']);
  }
  # SUCCESS, ret is the SA_INIT response
  else if (hdr['np'] == IKE2_PAYLOAD_SA)
    return ike_status(STATUS_SUCCESS, ret);
  else
    return ike_status(STATUS_FAILURE_UNEXPECTED, 'Unexpected first payload type ('+hdr['np']+') found in the response.');

}

#
# Wrappers
#
function ike2_parse()
{
  local_var pdu;

  pdu = _FCT_ANON_ARGS[0];
  return ike_parse(pdu);
}
function ike2_pcap_sendrecv(data, filter, timeout)
{
  return ike_pcap_sendrecv(data:data, filter:filter, timeout:timeout);
}

function ike2_sendrecv(socket, data)
{
  return ike_sendrecv(socket: socket, data: data);
}

function ike2_attr(type, value)
{
  return ike_attr(type:type, value:value);
}

function ike2_cipher()
{
  local_var id, keylen;

  id      = _FCT_ANON_ARGS[0];
  keylen  = _FCT_ANON_ARGS[1];

  return ike_cipher(id, keylen);

}
