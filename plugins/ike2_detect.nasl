#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("bpf_open")) exit(1, 'bpf_open() is not defined.');

include("compat.inc");

if (description)
{
 script_id(62695);
 script_version("$Revision: 1.5 $");
 script_cvs_date("$Date: 2016/02/15 20:09:31 $");

 script_name(english:"IPSEC Internet Key Exchange (IKE) Version 2 Detection");
 script_summary(english:"IPSEC IKE version 2 detection.");

 script_set_attribute(attribute:"synopsis", value:
"A VPN server is listening on the remote port.");
 script_set_attribute(attribute:"description", value:
"The remote host seems to be enabled to do Internet Key Exchange (IKE).
This is typically indicative of a VPN server. VPN servers are used to
connect remote hosts into internal resources.

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

 script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/24");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
 script_family(english:"Service detection");

 script_dependencies("ike_detect.nasl"); # ike2 detection should be after ike1 detection
 exit(0);
}

include('audit.inc');
include('byte_func.inc');
include('global_settings.inc');
include('misc_func.inc');
include('ike.inc');

if ( TARGET_IS_IPV6 ) exit(0, 'This plugin does not run over IPv6.');


# The initial exchange are as follows:
#
#   Initiator                         Responder
#   -------------------------------------------------------------------
#   HDR, SAi1, KEi, Ni  -->
#                                   <--  HDR, SAr1, KEr, Nr, [CERTREQ]
#
# Create a PROTO_IKE proposal with transforms permuted by
# encryption algorithms, integrity algorithms, DH groups, pseudo random functions, and
# key lengths
#
#
i = 0;
enc_list[i++] = ike2_cipher(IKE2_ENC_DES_IV64);
enc_list[i++] = ike2_cipher(IKE2_ENC_DES);
enc_list[i++] = ike2_cipher(IKE2_ENC_3DES);
enc_list[i++] = ike2_cipher(IKE2_ENC_RC5);
enc_list[i++] = ike2_cipher(IKE2_ENC_CAST);
enc_list[i++] = ike2_cipher(IKE2_ENC_BLOWFISH);
enc_list[i++] = ike2_cipher(IKE2_ENC_3IDEA);
enc_list[i++] = ike2_cipher(IKE2_ENC_DES_IV32);
enc_list[i++] = ike2_cipher(IKE2_ENC_NULL);
enc_list[i++] = ike2_cipher(IKE2_ENC_AES_CBC);
enc_list[i++] = ike2_cipher(IKE2_ENC_AES_CBC, 128);
enc_list[i++] = ike2_cipher(IKE2_ENC_AES_CBC, 192);
enc_list[i++] = ike2_cipher(IKE2_ENC_AES_CBC, 256);
enc_list[i++] = ike2_cipher(IKE2_ENC_AES_CTR);
enc_list[i++] = ike2_cipher(IKE2_ENC_AES_CTR, 128);
enc_list[i++] = ike2_cipher(IKE2_ENC_AES_CTR, 192);
enc_list[i++] = ike2_cipher(IKE2_ENC_AES_CTR, 256);

integ_list  = make_list(IKE2_INTEG_HMAC_MD5_96, IKE2_INTEG_HMAC_SHA1_96,
                       IKE2_INTEG_DES_MAC, IKE2_INTEG_KPDK_MD5, IKE2_INTEG_AES_XCBC_96);
group_list  = make_list(IKE_GROUP_MODP_768, IKE_GROUP_MODP_1024, IKE_GROUP_MODP_1536,
                        IKE_GROUP_MODP_2048, IKE_GROUP_MODP_3072, IKE_GROUP_MODP_4096);
prf_list    = make_list(IKE2_PRF_HMAC_MD5,IKE2_PRF_HMAC_SHA1, IKE2_PRF_HMAC_TIGER, IKE2_PRF_AES128_XCBC);


#
# If the group used in KE payload is not supported by the daemon,
# the daemon may not respond at all.
# So we need to try various group in the KE payload
#
foreach group (group_list)
{

  ispi = rand_str(length:8);
  status = ike2_sa_init(enc_list:enc_list, integ_list: integ_list, group_list: group_list,
                        prf_list: prf_list, ke_group: group, ispi:ispi);

  code = status['code'];

  #
  # If the daemon doesn't support any of our supplied encryption, integrity algorithms, DH groups, or PRFs,
  # It may not respond at all.
  #
  if(code == STATUS_FAILURE || code == STATUS_FAILURE_UNEXPECTED)
  {
    last_err_status = status;

    # Check if the IKE port is unreachable
    if(_ike_port_unreachable) break;
    else continue;
  }

  #
  # All other status codes indicate the remote IKEv2 daemon actually returns a valid IKEv2 PDU
  #

  # If we guessed the DH group wrong, the daemon will send an INVALID_KE_PAYLOAD notification.
  # In this case, it will send the selected DH group.
  # We will try ike2_sa_init() again with the selected group.
  if(code == IKN2_INVALID_KE_PAYLOAD)
  {
    ke_group = getword(blob: status['info'], pos:0);

    status = ike2_sa_init(enc_list:enc_list, integ_list: integ_list, group_list: group_list,
                      prf_list: prf_list, ke_group: ke_group, ispi:ispi);

    if(status['code'] ==  STATUS_SUCCESS)
    {
      ike = status['info'];
      payloads = ike['payloads'];
      hdr      = ike['hdr'];
    }
  }
  #
  # If we guess the DH group right, the daemon will send a SA payload
  #
  else if (code == STATUS_SUCCESS)
  {
    ike = status['info'];
    payloads = ike['payloads'];
    hdr      = ike['hdr'];
  }
  # else
  #   Unexpected status code, no payloads present for extracting VID
  #


  #
  # Some vendors will send VID payload(s) as well.
  # It seems that they do so only when they accept the proposal from the initiator.
  # That's why we need to send a second ike2_sa_init() with selected DH group, hoping
  # the daemon will send us some vendor ID payloads
  #
  vendor = NULL;
  foreach p (payloads)
  {
    if(p['type'] == IKE2_PAYLOAD_VID)
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
        set_kb_blob(name:'Services/ike2/'+ike_vendor[i],value:p['raw_data']);
      }
      #else          vendor += toupper(hexstr(p['raw_data'])) +'\n';
    }
  }
  if(! isnull(vendor))
  {
    report = 'Nessus was able to get the following IKE vendor ID(s) :\n'+vendor;
  }
  security_note(port:IKE_PORT, proto:'udp', extra:report);
  register_service(port: IKE_PORT, proto: 'ikev2', ipproto: 'udp');

  # Send an invalid AUTH in hope to prevent retransmission of IKE2_EXCH_SA_INIT response
  payloads = ike2_payload_auth(next:0, method:IKE2_AUTH_SHARED_KEY, data:crap(data:'A', length:128));
  rspi = hdr['rspi'];
  hdr = ike2_hdr( ispi: ispi,
                  rspi: rspi,
                  payload: IKE2_PAYLOAD_AUTH,
                  exch: IKE2_EXCH_AUTH,
                  flags: IKE2_FLAG_INITIATOR,
                  msgid: 0,
                  len:IKE_HDR_SIZE + strlen(payloads));

  pdu = hdr + payloads;
  ike2_pcap_sendrecv(data:pdu, timeout:1);
  exit(0);
}

code = last_err_status['code'];
msg  = last_err_status['info'];
if(code == STATUS_FAILURE) exit(0, msg);
if(code == STATUS_FAILURE_UNEXPECTED) exit(1, msg);
