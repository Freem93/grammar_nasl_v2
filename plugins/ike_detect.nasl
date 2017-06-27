#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("bpf_open")) exit(1, 'bpf_open() is not defined.');

include("compat.inc");

if (description)
{
 script_id(11935);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2016/06/13 20:14:28 $");

 script_name(english:"IPSEC Internet Key Exchange (IKE) Version 1 Detection");
 script_summary(english:"IPSEC IKE version 1 detection.");

 script_set_attribute(attribute:"synopsis", value:
"A VPN server is listening on the remote port.");
 script_set_attribute(attribute:"description", value:
"The remote host seems to be enabled to do Internet Key Exchange (IKE)
version 1. This is typically indicative of a VPN server. VPN servers
are used to connect remote hosts into internal resources. 

Make sure that the use of this VPN endpoint is done in accordance with
your corporate security policy. 

Note that if the remote host is not configured to allow the Nessus
host to perform IKE/IPSEC negotiations, Nessus won't be able to detect
the IKE service. 

Also note that this plugin does not run over IPv6.");
 script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it or filter incoming traffic
to this port.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/12/02");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('byte_func.inc');
include('ike.inc');

if ( TARGET_IS_IPV6 ) exit(0, 'This plugin does not run over IPv6.');

#
# Create a Proposal payload with multiple Transform payloads
#
i = 0;
enc_list[i++] = ike1_cipher(IKE1_ENC_AES_CBC);
enc_list[i++] = ike1_cipher(IKE1_ENC_AES_CBC, 256);
enc_list[i++] = ike1_cipher(IKE1_ENC_3DES_CBC);

hash_list       = make_list(IKE1_HASH_SHA1, IKE1_HASH_MD5);
auth_list       = make_list(IKE1_AUTH_PSK, IKE1_AUTH_SIG_RSA, IKE1_AUTH_ENC_RSA);
group_list      = make_list(IKE_GROUP_MODP_768, IKE_GROUP_MODP_1024, IKE_GROUP_MODP_1536);

proposal = ike1_phase1_proposal(enc_list:enc_list, hash_list: hash_list, auth_list:auth_list, group_list:group_list);

if(isnull(proposal)) audit(code: 1, AUDIT_FN_FAIL, 'ike1_phase1_proposal');

  
#
# Create a SA payload with ONE Transform payload
#
#
#  RFC 2409 section 5 says:
#   "If multiple offers are being
#   made for phase 1 exchanges (Main Mode and Aggressive Mode) they MUST
#   take the form of multiple Transform Payloads for a single Proposal
#   Payload in a single SA payload."
#
#  This means IKE1 can only have ONE SA payload, with only ONE Proposal embedded inside the
#  SA payload, and multiple Transform payloads embedded inside the Proposal payload
#
#
#
sa = ike1_payload_sa(next: IKE1_PAYLOAD_NONE,
                     doi: DOI_IPSEC,
                     situation: SIT_IDENTITY,
                     proposals: proposal
                     );
  
if(isnull(sa)) audit(code: 1, AUDIT_FN_FAIL, 'ike1_payload_sa');

# SA is the only payload in the first exchange in Main Mode
payloads = sa;


#
# Create a IKEv1 PDU
#
icookie = rand_str(length:8);
rcookie = crap(data:'\x00', length:8);
hdr = ike1_hdr( icookie: icookie,
                rcookie: rcookie,
                payload: IKE1_PAYLOAD_SA,
                exch: IKE1_MAIN_MODE, # ALL IKEv1 implementations MUST support Main Mode per RFC 2409
                flags: 0,
                msgid: 0,
                len:IKE_HDR_SIZE + strlen(payloads));
                 
pdu = hdr + payloads;
                   

#
# NB: make sure pdu fits in within an interface frame, or pcap won't send the frame
#
res = ike1_pcap_sendrecv(data:pdu);
if(isnull(res)) exit(0, 'No response from UDP port '+IKE_PORT+' to an IKEv1 Main Mode exchange.');

# Parse the response
ret = ike1_parse(res);
if(isnull(ret))
  audit(code:1, AUDIT_RESP_BAD, IKE_PORT,'an IKEv1 Main Mode exchange : invalid IKEv1 packet', 'UDP');

hdr       = ret['hdr'];
payloads  = ret['payloads'];
 
if(isnull(hdr))       exit(1,'Failed to get IKEv1 header in the response.');
if(isnull(payloads))  exit(1,'Failed to get any IKEv1 payload in the response.');
rcookie = hdr['rcookie'];

# Remote IKEv1 daemon has accepted one of our Transforms 
if(hdr['exch'] == IKE1_MAIN_MODE)
{
  # The daemon must respond with an SA as the FIRST payload
  if(hdr['np'] != IKE1_PAYLOAD_SA)
    audit(code:1, AUDIT_RESP_BAD, IKE_PORT,'a SA negotiation', 'UDP');
    
  # Some vendors will send VID payload(s) as well
  vendor = NULL;
  foreach p (payloads)
  {
    if(p['type'] == IKE1_PAYLOAD_VID)
    {
      sig_found = FALSE;
    	for (i = 0; ike_sig[i]; i++)
      {
        if (ike_sig[i] >< p['raw_data'])
        {
          sig_found = TRUE;
          break;
        }
      }
      if(sig_found)
      { 
         vendor += ike_vendor[i] + '\n';
         set_kb_blob(name:'Services/ike/'+ike_vendor[i],value:p['raw_data']);    
      }
      #else          vendor += toupper(hexstr(p['raw_data'])) +'\n';
    }
  }
  if(! isnull(vendor))
    report = 'Nessus was able to get the following IKE vendor ID(s):\n'+vendor;
  
  security_note(port:IKE_PORT, extra:report, proto:'udp');
  register_service(port: IKE_PORT, proto: 'ikev1', ipproto: 'udp');
  
  #
  # Some IKEv1 implementations (Cisco IOS and Openswan) will retransmit the response several times,
  # thinking that we might have not received the response in the first exchange because
  # we have never sent the second exchange.
  #
  # Since we will not and cannot complete the entire Main Mode exchange due to the lack of
  # authentication credential (i.e. Pre-Shared key, certificates, etc), we could either do:
  # 
  # 1) sleep some time to wait for the retransmission to finish (it could take up to 1 minute), or
  # 2) send something bad/invalid to the IKEv1 daemon to cause it to terminate the retransmit state, or
  # 3) do nothing
  #
  # Delete payload is supposed to be sent After the ISAKMP SA is created, and preceded by a HASH payload.
  #
  # Here we send a single Delete payload without the ISAKMP SA being created, and with a wrong exchange type.
  # The correct exchange type would be ISAKMP_EXCH_INFORMATIONAL
  #
  # Different implementation responds differently:
  #   - Cisco IOS 12.4 stops the retransmission.
  #   - Openswan sends a PAYLOAD_MALFORMED notification and continue to send retransmission
  # 
  # 
  
  delete = ike1_payload_delete(next:IKE1_PAYLOAD_NONE, doi: DOI_IPSEC, 
                              proto:0, spi_size:16, 
                              spi_list:make_list(icookie+rcookie)
                              );
  hdr = ike1_hdr( icookie: icookie,
                rcookie: rcookie,
                payload: IKE1_PAYLOAD_DELETE,
                exch: IKE1_MAIN_MODE,
                flags: 0,
                msgid: 0,
                len:IKE_HDR_SIZE + strlen(delete));
                 
  pdu = hdr + delete;
  ike1_pcap_sendrecv(data:pdu, timeout:1);
  
  # Wait for retransmission to finish
  #sleep(60);

}
# Remote IKEv1 daemon didn't accept our proposal.
# It should send us a ISAKMP_EXCH_INFORMATIONAL exchange with a Notification payload
else if(hdr['exch'] == ISAKMP_EXCH_INFORMATIONAL)
{
  notify_found = FALSE;
  foreach p (payloads)
  {
    if(p['type'] == IKE1_PAYLOAD_NOTIFY)
    {
      notify_found = TRUE;
      break;
    }
  }
  
  if(! notify_found)
    audit(code:1, AUDIT_RESP_BAD, IKE_PORT,'an SA negotiation : Notification payload not found in an Informational Exchange.', 'UDP');
    
  security_note(port:IKE_PORT, proto:'udp');
  register_service(port: IKE_PORT, proto: 'ikev1', ipproto: 'udp');
}
# Unexpected exchange type
else exit(1, 'The service listening on UDP port '+IKE_PORT+' returned an unexpected exchange type ('+hdr['exch']+').');
