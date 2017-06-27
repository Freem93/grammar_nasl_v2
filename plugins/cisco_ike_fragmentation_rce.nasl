#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89033);
  script_version("$Revision: 1.8 $");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/05/24");

  script_cve_id("CVE-2016-1287", "CVE-2016-1344");
  script_bugtraq_id(83161);
  script_osvdb_id(134373, 136250);
  script_xref(name:"TRA", value:"TRA-2016-06");
  script_xref(name:"CERT", value:"327976");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux29978");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux42019");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux38417");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160210-asa-ike");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-ios-ikev2");

  script_name(english:"Cisco ASA / IOS IKE Fragmentation Vulnerability");
  script_summary(english:"Checks the IKEv2 response from Cisco device.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Adaptive Security Appliance (ASA) or device running
IOS / IOS XE is affected by one of the following vulnerabilities in
the Internet Key Exchange (IKE) implementation :

  - An overflow condition exists in both the IKE and IKEv2
    implementations due to improper validation of
    user-supplied input when handling UDP packets. An
    unauthenticated, remote attacker can exploit this issue,
    via specially crafted UDP packets, to cause a buffer
    overflow condition, resulting in a denial of service or
    the execution of arbitrary code. (CVE-2016-1287)

  - A denial of service vulnerability exists in the IKEv2
    implementation due to improper handling of fragmented
    IKEv2 packets. An unauthenticated, remote attacker can
    exploit this issue, via specially crafted UDP packets,
    to cause the device to reload. (CVE-2016-1344)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160210-asa-ike
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eafc4e71");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-ios-ikev2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea61d7e9");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-06");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security
Advisories cisco-sa-20160210-asa-ike and cisco-sa-20160323-ios-ikev2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  exit(0);
}

include('audit.inc');
include('byte_func.inc');
include('global_settings.inc');
include('misc_func.inc');
include('ike.inc');
include('dump.inc');

function hdump(maxsize)
{
  local_var data, truncated;
  
  data = _FCT_ANON_ARGS[0];
  if(isnull(maxsize))
    maxsize = 64;

  truncated = FALSE;
  if(strlen(data) > maxsize)
  {
    data = substr(data, 0, maxsize - 1);
    truncated = TRUE;
  }

  data = hexdump(ddata: data);
  if(truncated)
    data += '(...truncated.)\n';
   
  return data;   
} 

function mk_msg(ispi, rspi, np, exch, flags, msgid, len, payloads)
{
  local_var hdr;
 
  if(isnull(len))
    len = 28 + strlen(payloads);  
  
  hdr = ike2_hdr(ispi:ispi, rspi:rspi, payload:np, exch:exch, flags:flags, msgid:msgid, len:len);

  return (hdr + payloads);
}


#
# MAIN
#

port = IKE_PORT;
soc = open_sock_udp(port);
if(! soc)
  audit(AUDIT_SOCK_FAIL, port, 'udp');

# Cisco ASA supports the following encryption algorithms
i = 0;
enc_list[i++] = ike2_cipher(2);
enc_list[i++] = ike2_cipher(3);
enc_list[i++] = ike2_cipher(11);
enc_list[i++] = ike2_cipher(12);
enc_list[i++] = ike2_cipher(12, 192);
enc_list[i++] = ike2_cipher(12, 256);
enc_list[i++] = ike2_cipher(20);
enc_list[i++] = ike2_cipher(20, 192);
enc_list[i++] = ike2_cipher(20, 256);

# Cisco ASA supports the following integrity algorithms
integ_list  = make_list(1, 2, 12, 13, 14);

# Cisco ASA supports the following DH groups 
group_list  = make_list(1, 2, 5, 14, 19, 20, 21, 24);

# Cisco ASA supports the following PRF algorithms
prf_list    = make_list(1, 2, 5, 6, 7);


# SA payload 
prop = ike2_proposal_ike(enc_list: enc_list, integ_list: integ_list, group_list:group_list,
                       prf_list:prf_list);

sa = ike2_payload_sa(next:IKE2_PAYLOAD_KE, proposals:prop);

# Nonce payload
nonce = ike2_payload(next: IKE2_PAYLOAD_VID, data:rand_str(length:32));

# Cisco Fragmentation VID 
vid_frag = ike2_payload(next: 0, data:hex2raw(s:"4048b7d56ebce88525e7de7f00d6c2d3"));


# Do 3 IKE_SA_INIT attempts in case we guessed the DH Group Wrong and handle
# COOKIE challenge

# we guess DH group 2
ke_group = 2; 

ispi = rand_str(length:8);
for (i = 0; i < 3; i++)
{ 
  # ASA supports the following DH groups
  if (ke_group == 1)
    dhpub_len = 96;
  else if(ke_group == 2)
    dhpub_len = 128;
  else if(ke_group == 5)
    dhpub_len = 192;
  else if(ke_group == 14)
    dhpub_len = 256;
  else if(ke_group == 19)
    dhpub_len = 64;
  else if(ke_group == 20)
    dhpub_len = 96;
  else if(ke_group == 21)
    dhpub_len = 132;
  else # DH group 24
    dhpub_len = 256;
    
  dhpub = rand_str(length: dhpub_len);
  ke = ike2_payload_ke(next:IKE2_PAYLOAD_NONCE, group:ke_group, data:dhpub);
  if(isnull(ke)) exit(1,'Failed to create a KE payload.');

  if(cookie)
  {
    payloads = cookie + sa + ke + nonce + vid_frag ;
    first_pl = IKE2_PAYLOAD_NOTIFY;
  }
  else
  {
    payloads = sa + ke + nonce + vid_frag ;
    first_pl = IKE2_PAYLOAD_SA;
  }
  msg = mk_msg( ispi: ispi,
                  rspi: crap(data:'\x00', length:8),
                  np: first_pl,
                  exch: IKE2_EXCH_SA_INIT, 
                  flags: IKE2_FLAG_INITIATOR,
                  msgid: 0,
                  payloads: payloads);

  res = ike2_sendrecv(socket:soc, data:msg);
  if(isnull(res)) 
    audit(AUDIT_RESP_NOT, port, 'to an IKE_SA_INIT message', 'UDP');

  pkt = SHA1(res);
  seen[pkt]++;
  
  # Parse the response
  ret = ike2_parse(res);
  if(isnull(ret) || isnull(ret['hdr']) || isnull(ret['payloads'])) 
  {
    exit(1, 'Failed to parse IKE_SA_INIT response: \n' + hdump(res));
  }

  # Got a Notification payload, possible reasons: 
  #   1) We guessed the DH group wrong
  #   2) IKEv2 daemon configured to send COOKIE challenges 
  #   3) IKEv2 daemon doesn't accept our proposal 
  hdr = ret['hdr'];
  payloads = ret['payloads'];
  if(hdr['np'] ==  IKE2_PAYLOAD_NOTIFY)
  {
    notify = payloads[0];
    notify = ike2_parse_notify(notify['raw_data']);
    if(isnull(notify) || isnull(notify['type']))
    {
      exit(1,'Failed to parse IKEv2 Notification payload in response: \n' + hdump(res));
    }
    if(notify['type'] == IKN2_INVALID_KE_PAYLOAD)
    {
      if(strlen(notify['data']) == 2)
      {
        ke_group = getword(blob: notify['data'], pos:0); 

        # Check if we support this ke DH group
        if(item_in_list(list: group_list, item: ke_group))
        {
          continue; 
        }
        else
        {
          exit(0, 'IKEv2 DH group ' + ke_group + ' not supported.'); 
        }
      } 
      else
      {
        exit(1, 'Missing or invalid data in INVALID_KE_PAYLOAD notification : \n' + hdump(res));   
      }
    }
    else if(notify['type'] == IKN2_COOKIE)
    {
      if(strlen(notify['data']) != 0)
      {
        data = '\x01' + '\x00' + mkword(IKN2_COOKIE) + notify['data'];
        cookie = ike2_payload(next:IKE2_PAYLOAD_SA, data:data); 
        continue;
      }
      else
      {
        exit(1, 'Missing data in COOKIE notification : \n' + hdump(res));   
      }
    }
    # IKEv2 daemon does not accept our proposal.
    # Since we specified all ASA supported transforms, seeing this
    # probably mean we are not dealing with an ASA.
    else if(notify['type'] == IKN2_NO_PROPOSAL_CHOSEN)
    {
      exit(0, 'No proposal chosen, remote IKEv2 daemon probably not Cisco ASA.'); 
    }
    else
    {
      exit(1, 'Unexpected notification in response : \n' + hdump(res));
    }
  }
  # We have an IKE SA!
  else if(hdr['np'] ==  IKE2_PAYLOAD_SA)
  {
    break;
  }
  else
  {
    exit(1, 'Unexpected first payload in response : \n' + hdump(res));
  }
}

cisco = 0;
cisco_frag = 0;
sa_r = ke_r = n_r = NULL;
foreach pl (payloads)
{
  if(pl['type'] == IKE2_PAYLOAD_SA)
  {
    sa_r = pl['raw_data'];
  }
  else if (pl['type'] == IKE2_PAYLOAD_KE)
  {
    ke_r = pl['raw_data'];
  }
  else if (pl['type'] == IKE2_PAYLOAD_NONCE)
  {
    n_r = pl['raw_data'];
  }
  else if (pl['type'] == IKE2_PAYLOAD_VID)
  {
    if ('CISCO' >< pl['raw_data'])
      cisco++;
    else if (pl['raw_data'] == hex2raw(s:"4048b7d56ebce88525e7de7f00d6c2d3"))
      cisco_frag = TRUE;
  }
  
}

if(!sa_r || !ke_r || !n_r)
{
 exit(1, 'Failed to get SA, KE, or NONCE payload in the IKE_INIT_SA response.');
}

if(! cisco)
  exit(0, 'Remote IKEv2 daemon does not appear to be associated with Cisco.');

if(! cisco_frag)
  exit(0, 'Remote IKEv2 daemon does not appear to support or have Cisco IKE fragmentation enabled.');

rspi = hdr['rspi'];
msgid = 1;
# bad msg: invalid rspi in a bogus Encrypted Payload
pl_enc = ike2_payload(next:0, data:crap(data:'BAAD', length:16));
bad_msg = mk_msg( ispi: ispi,
                rspi: rspi,
                np: IKE2_PAYLOAD_ENCRYPTED,
                exch: IKE2_EXCH_SA_INIT,
                flags: IKE2_FLAG_INITIATOR,
                msgid: msgid,
                payloads: pl_enc);


id = 1; 
seq = 1;
# Fragment1: empty fragment 
# - Patched ASA will drop it
# - Vulnerable ASA will accept and store it
frag1 = '\x00' + '\x00' +  mkword(8) + mkword(id) + mkbyte(seq++) + mkbyte(0); 

# Fragment2: bad ikev2 msg 
# - Vulnerable ASA will assemble the 2 fragments, and process the assembled msg, 
#   seeing an invalid msg, will return a notification payload.
#    
# - Patched one doesn't assemble because it's missing the first fragment.
#   So it will not response.  
frag2 = '\x00' + '\x00' + mkword(8 + strlen(bad_msg)) + mkword(id) + mkbyte(seq++) + mkbyte(1) + bad_msg; 

msg = mk_msg( ispi: ispi,
                rspi: rspi,
                np: 132,
                exch: IKE2_EXCH_AUTH,
                flags: IKE2_FLAG_INITIATOR,
                msgid: msgid,
                payloads: frag1);
send(socket:soc, data:msg);

msg = mk_msg( ispi: ispi,
                rspi: rspi,
                np: 132, 
                exch: IKE2_EXCH_AUTH,
                flags: IKE2_FLAG_INITIATOR,
                msgid: msgid,
                payloads: frag2);
send(socket:soc, data:msg);
res = recv(socket: soc, length:1024);

# Check if it a retransmitted IKE_INIT_SA response
if(res)
{
  pkt = SHA1(res);
  cnt = 0;
  while(seen[pkt])
  {
    res = recv(socket:soc, length:1024); 
    pkt = SHA1(res);
    if(cnt++ > 5)
      exit(1, 'Too many retransmitted responses.');
  }
  seen[pkt]++;
}
close(soc);

# Vulnerable target returns an INVALID-SYNTAX notification 
if(res)
{
  ret = ike2_parse(res);
  if(isnull(ret) || isnull(ret['hdr']) || isnull(ret['payloads']))
  {
    exit(1, 'Failed to parse IKEv2 response : \n' + hdump(res));   
  }

  pl_notify = NULL;
  foreach pl (ret['payloads'])
  {
    if(pl['type'] == IKE2_PAYLOAD_NOTIFY)
    {
      pl_notify = pl;
      break; 
    }
  }

  if(! pl_notify)
  {
    exit(1, 'IKEv2 Notification payload not found in response : \n' + hdump(res)); 
  }
  notify = ike2_parse_notify(pl_notify['raw_data']);
  if(isnull(notify) || isnull(notify['type']))
  {
    exit(1,'Failed to parse IKEv2 notification payload in response : \n' + hdump(res));
  }
  if(notify['type'] == 7)
  {
    security_hole(port:port, proto:"udp");
  } 
  else
  {
    audit(AUDIT_RESP_BAD, 'Cisco IKE fragmentation messages, response : \n' + hdump(res)); 
  }
}
# Patched target won't assemble the fragments, so no response
else
{
  audit(AUDIT_HOST_NOT, 'affected');   
}
