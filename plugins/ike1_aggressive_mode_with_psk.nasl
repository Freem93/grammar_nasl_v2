#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("bpf_open")) exit(1, 'bpf_open() is not defined.');

include("compat.inc");

if (description)
{
 script_id(62694);
 script_version("$Revision: 1.7 $");
 script_cvs_date("$Date: 2015/11/18 21:03:57 $");

 script_cve_id("CVE-2002-1623");
 script_bugtraq_id(7423);
 script_osvdb_id(3820, 34836);
 script_xref(name:"CERT", value:"886601");

 script_name(english:"Internet Key Exchange (IKE) Aggressive Mode with Pre-Shared Key");
 script_summary(english:"Performs IKE Aggressive Mode exchange using Pre-Shared key authentication");

 script_set_attribute(attribute:"synopsis", value:
"The remote IKEv1 service supports Aggressive Mode with Pre-Shared key.");
 script_set_attribute(attribute:"description", value:
"The remote Internet Key Exchange (IKE) version 1 service seems to
support Aggressive Mode with Pre-Shared key (PSK) authentication. Such
a configuration could allow an attacker to capture and crack the PSK
of a VPN gateway and gain unauthorized access to private networks.");
 script_set_attribute(attribute:"solution", value:
"- Disable Aggressive Mode if supported.
- Do not use Pre-Shared key for authentication if it's possible.
- If using Pre-Shared key cannot be avoided, use very strong keys.
- If possible, do not allow VPN connections from any IP addresses.

Note that this plugin does not run over IPv6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  # http://www.cisco.com/en/US/tech/tk583/tk372/technologies_security_notice09186a008016b57f.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07b12cbb"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ernw.de/download/pskattack.pdf"
  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.vpnc.org/ietf-ipsec/99.ipsec/msg01451.html"
  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/bid/7423"
  );

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/09/03");
 script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/24");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
 script_family(english:"General");

 script_dependencies("ike_detect.nasl");
 script_require_keys("Services/udp/ikev1");
 exit(0);
}


include('byte_func.inc');
include('global_settings.inc');
include('misc_func.inc');
include('ike.inc');


#
# Make sure IKEv1 is detected
#
if (!get_kb_item('Services/udp/ikev1'))
  exit(0, 'IKE version 1 service was not detected on UDP port ' + IKE_PORT + '.');
  

if ( TARGET_IS_IPV6 ) exit(0, 'This plugin does not run over IPv6.');

#
# Aggressive mode with a Pre-Shared key is described as follows (section 5.4, RFC 2409)
#
#
#            Initiator                        Responder
#           -----------                      -----------
#            HDR, SA, KE, Ni, IDii -->
#                                  <--    HDR, SA, KE, Nr, IDir, HASH_R
#            HDR, HASH_I           -->



#
# Create a list of Transform Payloads with Pre-Shared key as authentication
#
#
i = 0;
enc_list[i++] = ike1_cipher(IKE1_ENC_AES_CBC);
enc_list[i++] = ike1_cipher(IKE1_ENC_AES_CBC, 128);
enc_list[i++] = ike1_cipher(IKE1_ENC_AES_CBC, 192);
enc_list[i++] = ike1_cipher(IKE1_ENC_AES_CBC, 256);
enc_list[i++] = ike1_cipher(IKE1_ENC_3DES_CBC);
enc_list[i++] = ike1_cipher(IKE1_ENC_DES_CBC);

hash_list     = make_list(IKE1_HASH_SHA1, IKE1_HASH_MD5, IKE1_HASH_SHA2_256, IKE1_HASH_SHA2_384, IKE1_HASH_SHA2_512);
 

group_list  = make_list(IKE_GROUP_MODP_768,  IKE_GROUP_MODP_1024, IKE_GROUP_MODP_1536, 
                          IKE_GROUP_MODP_2048, IKE_GROUP_MODP_3072, IKE_GROUP_MODP_4096,
                          IKE_GROUP_MODP_6144, IKE_GROUP_MODP_8192);



#
# DH group cannot be negotiated in Aggressive Mode as a group must be used to compute the DH public value in the KE payload.
# Here we try one group at a time
#
foreach group (group_list)
{

  # Create a Proposal with ONE Transform
  proposal = ike1_phase1_proposal(enc_list:enc_list, hash_list: hash_list, auth_list:make_list(IKE1_AUTH_PSK), group_list:make_list(group));
                              
  # Create a SA with ONE Proposal and ONE Transform
  sa = ike1_payload_sa(next: IKE1_PAYLOAD_KE,
                       doi: DOI_IPSEC,
                       situation: SIT_IDENTITY,
                       proposals: proposal
                       );

                       
  #
  # Key Exchange Payload
  #
  # Generate the client private key,
  x = rand_str(length:16);

  # Compute g^x mod p.
  dh_x = bn_mod_exp(IKE_DH_GENERATOR_2, x, IKE_DH_GROUP[group]);
  ke = ike1_payload(next:IKE1_PAYLOAD_NONCE, data:dh_x);

  #
  # Nonce Payload
  #
  nonce = ike1_payload(next: IKE1_PAYLOAD_ID, data:rand_str(length:32));

  #
  # ID Payload
  #
  id = ike1_payload_id(next: IKE1_PAYLOAD_NONE, type:IPSEC_ID_IPV4_ADDR, proto:0, port:0,
                        data: this_host_raw());


  payloads = sa  + ke + nonce + id;
                         

  icookie = rand_str(length:8);
  rcookie = crap(data:'\x00', length:8);
  hdr = ike1_hdr(icookie: icookie,
                   rcookie: rcookie,
                   payload: IKE1_PAYLOAD_SA,
                   exch: IKE1_AGGRESSIVE_MODE,
                   flags: 0,
                   msgid: 0,
                   len:IKE_HDR_SIZE + strlen(payloads));
                   
  data = hdr + payloads;
                   
  res = ike1_pcap_sendrecv(data:data);
  if(isnull(res)) continue;
 
  # Parse the response  
  ret = ike1_parse(res);
  if(isnull(ret)) continue;
  
  hdr = ret['hdr'];
  if(isnull(hdr)) continue;
  
  #
  # A IKEv1 daemon that doesn't support Aggressive Mode may not respond. 
  #
  # A IKEv1 daemon that supports Aggressive Mode will compare its configured
  # policy against the offered proposal based on its configured encryption, 
  # hash algorithms, authentication methods, and DH groups.
  # If the proposal is accepted, it will respond with a IKE1_AGGRESSIVE_MODE exchange.
  # If the proposal is not accepted, it will respond with a IKE1_EXCH_INFORMATIONAL exchange
  # with a NO-PROPOSAL-CHOSEN notification. In this case, we cannot tell which crypto 
  # parameter (enc, hash, auth, dh group) it doesn't support.
  #
  # Since we try a fairly long list of Transforms, each with PSK as authentication in it, 
  # IKEv1 daemon supporting Aggressive Mode with PSK will respond with a IKE1_AGGRESSIVE_MODE exchange type.
  # Note that we still can get False Negative as the list is not exhaustive.
  #
  #
  if(hdr['exch'] == IKE1_AGGRESSIVE_MODE && hdr['np'] == IKE1_PAYLOAD_SA)
  {
    security_warning(port:IKE_PORT, proto:'udp');
    exit(0);
  }
  
}

exit(0, 'The IKE version 1 service listening on UDP port '+IKE_PORT+' does not appear to support Aggressive Mode with Pre-Shared key.');
