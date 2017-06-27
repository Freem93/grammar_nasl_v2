#TRUSTED 8ca4c5266520d43ea5709980fa60965cea8456729e55bfff8cd07d66ba84f404d6cbb6bc2ee0dac6355b14ce014636f327f2eda4e525a2272d95476987bbc9c2b84aa387d1b7311fe5f29bbabe74dc926b7b43b8375679711aaf82321ceb5ce21673d105a333122d41e8329514b391f980b459e7b84ea1a23f44239bb85232226c83b01c46d1735a3af879672613a068d61dae43bb4be085095dfedcda0731ed3567131f7c125f4ffd217dd8d7ae6572dfbb854fb0e3619211e336391199bf27ce65b894e7c68c91791d3d656747c2566ade02ef0553fa96f8a74dbbbad62e333727b9df447bd84f65082109a3d71399890397a027edae6d512238c25babac35dfffe0e2436856b603f8bd267fb6c2289da658d68482c9e98b1f04f7a68731c7afd394befbcc31456c60cec74acf50f12710fbf82e8e7f0de4b4b1b8aa05d96ac2aff099a4646c2ea05cffe6c00eb024dbee26276e87777ac4849aa5ff47b53868f0722266c5cbfb86aa3afbd8ad58baf617546465739e6e2971f7c7237baf67a41d69d17ad15b62900c6c856adf50508e62488c98ef5a83f9bedf86c87a326d575b5b1d49a313c6dac799355051f2bba68e0a9a452ea73bf12322b9b6f342e6e7b1c0147d99e2a5d7348e659075e9f954a5f409253c78a28ff18a820f3b60bd4ac10bc96e8f9765dae7fa02f5ce9d1537f3821707375faa0eeed9269c815875
#
# (C) Tenable Network Security, Inc.
#

if ( !defined_func("socket_get_error") ) audit(AUDIT_FN_UNDEF, "socket_get_error");

include("compat.inc");

if (description)
{
  script_id(77200);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/18");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0076",
    "CVE-2014-0195",
    "CVE-2014-0198",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-3470"
  );
  script_bugtraq_id(
    66363,
    66801,
    67193,
    67898,
    67899,
    67900,
    67901
  );
  script_osvdb_id(
    104810,
    105763,
    106531,
    107729,
    107730,
    107731,
    107732
  );
  script_xref(name:"CERT", value:"978508");

  script_name(english:"OpenSSL 'ChangeCipherSpec' MiTM Vulnerability");
  script_summary(english:"Checks if the remote host incorrectly accepts a 'ChangeCipherSpec' message.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability that could allow
sensitive data to be decrypted.");
  script_set_attribute(attribute:"description", value:
"The OpenSSL service on the remote host is vulnerable to a
man-in-the-middle (MiTM) attack, based on its acceptance of a
specially crafted handshake.

This flaw could allow a MiTM attacker to decrypt or forge SSL messages
by telling the service to begin encrypted communications before key
material has been exchanged, which causes predictable keys to be used
to secure future traffic.

Note that Nessus has only tested for an SSL/TLS MiTM vulnerability
(CVE-2014-0224). However, Nessus has inferred that the OpenSSL service
on the remote host is also affected by six additional vulnerabilities
that were disclosed in OpenSSL's June 5th, 2014 security advisory :

  - An error exists in the 'ssl3_read_bytes' function
    that permits data to be injected into other sessions
    or allows denial of service attacks. Note that this
    issue is exploitable only if SSL_MODE_RELEASE_BUFFERS
    is enabled. (CVE-2010-5298)

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    allows nonce disclosure via the 'FLUSH+RELOAD' cache
    side-channel attack. (CVE-2014-0076)

  - A buffer overflow error exists related to invalid DTLS
    fragment handling that permits the execution of
    arbitrary code or allows denial of service attacks.
    Note that this issue only affects OpenSSL when used
    as a DTLS client or server. (CVE-2014-0195)

  - An error exists in the 'do_ssl3_write' function that
    permits a NULL pointer to be dereferenced, which could
    allow denial of service attacks. Note that this issue
    is exploitable only if SSL_MODE_RELEASE_BUFFERS is
    enabled. (CVE-2014-0198)

  - An error exists related to DTLS handshake handling that
    could allow denial of service attacks. Note that this
    issue only affects OpenSSL when used as a DTLS client.
    (CVE-2014-0221)

  - An error exists in the 'dtls1_get_message_fragment'
    function related to anonymous ECDH cipher suites. This
    could allow denial of service attacks. Note that this
    issue only affects OpenSSL TLS clients. (CVE-2014-3470)

OpenSSL did not release individual patches for these vulnerabilities,
instead they were all patched under a single version release. Note
that the service will remain vulnerable after patching until the
service or host is restarted.");
  # http://ccsinjection.lepidum.co.jp/blog/2014-06-05/CCS-Injection-en/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5709faa");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/06/05/earlyccs.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:
"OpenSSL 0.9.8 SSL/TLS users (client and/or server) should upgrade to
0.9.8za. OpenSSL 1.0.0 SSL/TLS users (client and/or server) should
upgrade to 1.0.0m. OpenSSL 1.0.1 SSL/TLS users (client and/or server)
should upgrade to 1.0.1h.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_ports(443, "SSL/Supported");
  exit(0);
}

include("acap_func.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("imap_func.inc");
include("ldap_func.inc");
include("nntp_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");
include("telnet2_func.inc");
include("x509_func.inc");
include("xmpp_func.inc");
include("rsync.inc");
include("audit.inc");
include("string.inc");

global_var _ssl;

##
# Get cipher description.
#
# @return Value of ciphers_desc[<name>] from ssl_funcs.inc.
##
function ssl3_get_cipher_desc()
{
  local_var cipher, name;

  if (!isnull(_ssl['cipher_desc']))
    return _ssl['cipher_desc'];

  cipher = _ssl['cipher'];
  name = cipher_name(id:cipher);
  if (isnull(name)) return NULL;

  return ciphers_desc[name];
}

##
# Checks whether a cipher is in a list of cipher suites.
#
# @anonparam cipher Cipher in question.
# @anonparam ciphers List of cipher suites.
#
# @return TRUE for success, FALSE otherwise.
##
function ssl3_cipher_in_list()
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
# Split the key block into IVs, cipher keys, and MAC keys.
#
# @anonparam keyblk Key block derived from the master secret.
#
# @return TRUE for success, FALSE otherwise.
##
function ssl3_set_keys()
{
  local_var desc, mac_size, iv_size, key_size, keyblk, pos;

  desc = ssl3_get_cipher_desc();
  if (isnull(desc)) return FALSE;

  keyblk = _FCT_ANON_ARGS[0];

  # Determine the size of the key block's fields.
  if      ('Mac=SHA1' >< desc) mac_size = 20;
  else if ('Mac=MD5'  >< desc) mac_size = 16;
  else return FALSE;

  if      ('Enc=3DES-CBC(168)' >< desc) { key_size = 24; iv_size =  8; }
  else if ('Enc=DES-CBC(56)'   >< desc) { key_size =  8; iv_size =  8; }
  else if ('Enc=AES-CBC(128)'  >< desc) { key_size = 16; iv_size = 16; }
  else if ('Enc=AES-CBC(256)'  >< desc) { key_size = 32; iv_size = 16; }
  else return FALSE;

  # Ensure the block is big enough.
  if (strlen(keyblk) < 2 * (mac_size + key_size + iv_size))
    return FALSE;

  # Extract the data from the key block.
  pos = 0;
  _ssl['enc_mac_key'] = substr(keyblk, pos, pos + mac_size - 1); pos += mac_size;
  _ssl['dec_mac_key'] = substr(keyblk, pos, pos + mac_size - 1); pos += mac_size;
  _ssl['enc_key']     = substr(keyblk, pos, pos + key_size - 1); pos += key_size;
  _ssl['dec_key']     = substr(keyblk, pos, pos + key_size - 1); pos += key_size;
  _ssl['enc_iv']      = substr(keyblk, pos, pos + iv_size  - 1); pos += iv_size;
  _ssl['dec_iv']      = substr(keyblk, pos, pos + iv_size  - 1);

  return TRUE;
}

##
# Hashes data.
#
# @anonparam data Data to be hashed.
#
# @return Message digest of the given data.
##
function ssl3_hash()
{
  local_var data, desc;

  desc = ssl3_get_cipher_desc();
  if (isnull(desc)) return NULL;

  data = _FCT_ANON_ARGS[0];

  if ('Mac=SHA1' >< desc)
    return SHA1(data);

  if ('Mac=MD5' >< desc)
    return MD5(data);

  return NULL;
}

##
# Compute the HMAC of the data.
#
# @anonparam data Data to be HMACed.
# @anonparam key The key for the HMAC algorithm.
#
# @return HMAC of the given data.
##
function ssl3_hmac()
{
  local_var  data, desc, key;

  desc = ssl3_get_cipher_desc();
  if (isnull(desc)) return NULL;

  key = _FCT_ANON_ARGS[0];
  data = _FCT_ANON_ARGS[1];

  if ('Mac=SHA1' >< desc)
    return HMAC_SHA1(key:key, data:data);

  if ('Mac=MD5' >< desc)
    return HMAC_MD5(key:key, data:data);

  return NULL;
}

##
# Computes the MAC of the data.
#
# @param client Whether the data is from the client or server.
# @param data The data to be calculate the MAC of.
# @param type The type of the record.
#
# @returns The MAC of the given data, in protocol-specific form.
##
function ssl3_mac(client, data, type)
{
  local_var key, seq;

  if (isnull(client))
    client = TRUE;

  if (client)
  {
    key = _ssl['enc_mac_key'];
    seq = _ssl['clt_seq'];
  }
  else
  {
    key = _ssl['dec_mac_key'];
    seq = _ssl['srv_seq'];
  }

  # Encode the client sequence number.
  seq = mkdword(0) + mkdword(seq);

  if (_ssl['version'] == SSL_V3)
  {
    return ssl3_hash(
      key +                            # Key
      crap(data:'\x5c', length:40) +   # O-Pad
      ssl3_hash(                       #
        key +                          # Key
        crap(data:'\x36', length:40) + # I-Pad
        seq +                          # 64-bit sequence number
        mkbyte(type) +                 # Record ID
        mkword(strlen(data)) +         # Data length
        data                           # Data
      )
    );
  }

  if (_ssl['version'] == TLS_10)
  {
    return ssl3_hmac(
      key,
      seq + tls_mk_record(type:type, data:data, version:TLS_10)
    );
  }

  return NULL;
}

##
# Encrypt or decrypt data.
#
# @anon param data input data
# @param enc Whether to encrypt (TRUE) or decrypt (FALSE).
#
# @return Result of encrypting or decrypting the given data.
##
function ssl3_crypt(enc)
{
  local_var data, desc, iv, key, out, ret;

  desc = ssl3_get_cipher_desc();
  if (isnull(desc)) return NULL;

  data = _FCT_ANON_ARGS[0];

  if (enc)
  {
    key = _ssl['enc_key'];
    iv = _ssl['enc_iv'];
  }
  else
  {
    key = _ssl['dec_key'];
    iv = _ssl['dec_iv'];
  }

  if ('Enc=3DES-CBC(168)' >< desc)
  {
    if (enc)
      ret = tripledes_cbc_encrypt(data:data, key:key, iv:iv);
    else
      ret = tripledes_cbc_decrypt(data:data, key:key, iv:iv);
  }
  else if ('Enc=DES-CBC(56)' >< desc)
  {
    out = des_cbc_encrypt(data:data, key:key, iv:iv, encrypt:enc);
    if (enc)
      ret = make_list(out, substr(out, strlen(out) - 8));
    else
      ret = make_list(out, substr(data, strlen(data) - 8));
  }
  else if ('Enc=AES-CBC(128)' >< desc || 'Enc=AES-CBC(256)' >< desc)
  {
    if (enc)
      ret = aes_cbc_encrypt(data:data, key:key, iv:iv);
    else
      ret = aes_cbc_decrypt(data:data, key:key, iv:iv);
  }

  if (isnull(ret)) return NULL;

  # Update IV for the next block.
  if (enc)
    _ssl['enc_iv'] = ret[1];
  else
    _ssl['dec_iv'] = ret[1];

  return ret[0];
}

##
# Encrypt data with the block cipher.
#
# @anonparam data The data to be encrypted.
#
# @return The ciphertext of the given data.
##
function ssl3_encrypt()
{
  local_var data, block_size, padlen;

  data = _FCT_ANON_ARGS[0];

  # Calculate how much padding is needed to fill the block.
  block_size = strlen(_ssl['enc_iv']);
  padlen = block_size - (strlen(data) % block_size);

  # Append the padding to the data.
  data += crap(data:mkbyte(padlen - 1), length:padlen);

  return ssl3_crypt(data, enc:TRUE);
}

##
# Decrypt data with the block cipher.
#
# @anonparam data The data to be decrypted.
#
# @return The plaintext of the given data.
##
function ssl3_decrypt()
{
  return ssl3_crypt(_FCT_ANON_ARGS[0], enc:FALSE);
}

##
# Sets an error message
#
# @anonparam msg The error message.
#
# @return NULL.
##
function ssl3_set_error()
{
  _ssl['error'] = _FCT_ANON_ARGS[0];

  return NULL;
}

##
# Get last error message.
#
# @return Last error message.
##
function ssl3_get_lasterror()
{
  if (_ssl['version'] == TLS_10)
    return "[TLSv1] " + _ssl['error'];
  if (_ssl['version'] == SSL_V3)
    return "[SSLv3] " + _ssl['error'];
}

##
# Tries to make an SSL/TLS connection to the server.
#
# @return TRUE for success, FALSE otherwise.
##
function ssl3_connect()
{
  local_var cert, cipher, ckex, clt_finished, clt_random;
  local_var dh_privkey, pubkey;
  local_var dh_x, e, embedded_mac, embedded_srv_finished;
  local_var end, hs, i,keyblk, len, mac, mac_size;
  local_var real_master, empty_master, msg, n, padlen, parsed, pkt, plain, port;
  local_var premaster, rec, recs, skex, soc, srv_finished, srv_random;
  local_var start, version, x;

  # Get a socket to perform a handshake.
  port = _ssl['port'];
  soc = open_sock_ssl(port);
  if (!soc)
    return ssl3_set_error('Failed to connect to port ' + port + '.');

  version = _ssl['version'];
  cipher = _ssl['cipher'];

  # Make a ClientHello msg.
  msg =
    mkword(version) +                    # Client version
    dec2hex(num:unixtime()) +            # Challenge, epoch portion
    rand_str(length:28) +                # Challenge, random portion
    ssl_vldata_put(data:'', len:1) +     # Session ID
    ssl_vldata_put(data:cipher, len:2) + # Cipher spec
    ssl_vldata_put(data:'\x00', len:1) + # Compression spec
    ssl_vldata_put(data:tls_ext_ec(keys(curve_nid.tls)), len:2); # supported curves
  msg = ssl_mk_handshake_msg(data:msg, type:SSL3_HANDSHAKE_TYPE_CLIENT_HELLO);
  rec = ssl_mk_record(type:SSL3_CONTENT_TYPE_HANDSHAKE, data:msg, version:version);

  # Send the ClientHello record.
  send(socket:soc, data:rec);

  # Parse the ClientHello record.
  parsed = ssl_parse(blob:rec);
  clt_random = mkdword(parsed['time']) + parsed['random'];

  # Start collecting the bodies of handshake messages, which are used
  # to generate the encrypted Finished message.
  hs = substr(rec, 5, strlen(rec) - 1);

  # Read records one at a time. Expect to see at a minimum:
  # ServerHello, Certificate, and ServerHelloDone.
  while (TRUE)
  {
    # Receive records from the server.
    recs = recv_ssl(socket:soc);
    if (isnull(recs))
    {
      close(soc);
      return ssl3_set_error('Port ' + port + ': server did not respond to ClientHello.');
    }

    rec = ssl_find(
      blob:recs,
      'content_type', SSL3_CONTENT_TYPE_ALERT
    );
    if (!isnull(rec)) return ssl3_set_error('Port ' + port + ': server returned an alert when sent a ClientHello message.');

    # Collect the body of the message, including all records.
    hs += substr(recs, 5, strlen(recs) - 1);

    # ServerHello: Extract the random data for computation of keys.
    rec = ssl_find(
      blob:recs,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
    );

    if (!isnull(rec))
    {
      # Check handshake version returned by the server, and ensure
      # that it hasn't downgraded the version.
      if (rec['handshake_version'] != _ssl['version'])
      {
        close(soc);
        return ssl3_set_error('Port ' + port + ': SSL/TLS protocol version mismatch.');
      }

      srv_random = mkdword(rec['time']) + rec['random'];

      # Wacko SSL servers might return a cipher suite not in the
      # client's request list.
      if (!ssl3_cipher_in_list(mkword(rec['cipher_spec']), _ssl['cipher']))
      {
        close(soc);
        return ssl3_set_error('Port ' + port + ': server returned a cipher suite not in list supported by client.');
      }

      # Store the negotiated cipher suite.
      _ssl['cipher'] = rec['cipher_spec'];
      _ssl['cipher_desc'] = ssl3_get_cipher_desc();
    }

    # Certificate: Extract the server's public key.
    rec = ssl_find(
      blob:recs,
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
        return ssl3_set_error('Port ' + port + ': server certificate could not be parsed.');
      }

      cert = cert['tbsCertificate'];
    }

    # Server Key Exchange.
    rec = ssl_find(
      blob:recs,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE
    );

    if (!isnull(rec['data']))
      skex = ssl_parse_srv_kex(blob:rec['data'], cipher:_ssl['cipher_desc']);

    # Certificate Request.
    rec = ssl_find(
      blob:recs,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_CERTIFICATE_REQUEST
    );

    if (!isnull(rec['data']))
      _ssl['clt_cert_requested'] = TRUE;

    # Server Hello Done.
    rec = ssl_find(
      blob:recs,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE
    );

    if (!isnull(rec)) break;
  }

  # Packet will contain ClientCertificate, ClientKeyExchange,
  # ChangeCipherSpec, and Finished.
  pkt = '';

  # Create an empty client certificate if one is requested.
  if (_ssl['clt_cert_requested'])
  {
    # Send an empty certificate for now. TLSv1.0 says the client can
    # send an empty certificate, but not sure what SSLv3 says.
    msg = ssl_mk_handshake_msg(
      type : SSL3_HANDSHAKE_TYPE_CERTIFICATE,
      data : ssl_vldata_put(data:NULL,len:3)
    );
    hs += msg;

    rec = ssl_mk_record(type:SSL3_CONTENT_TYPE_HANDSHAKE, data:msg, version:version);
    pkt += rec;
  }

  # Process ServerCertificate and ServerKeyExchange messages.
  if (_ssl['cipher_desc'] =~ "Kx=RSA[(|]")
  {
    if (isnull(cert))
    {
      close(soc);
      return ssl3_set_error('Port ' + port + ': No server certificate was found.');
    }

    if (isnull(cert['subjectPublicKeyInfo']) || isnull(cert['subjectPublicKeyInfo'][1]))
    {
      close(soc);
      return ssl3_set_error('Port ' + port + ': A server certificate with an unsupported algorithm was found.');
    }

    n = cert['subjectPublicKeyInfo'][1][0];
    e = cert['subjectPublicKeyInfo'][1][1];
    if(isnull(n) || isnull(e))
    {
      close(soc);
      return ssl3_set_error('Port ' + port + ': Failed to extract public key from server certificate.');
    }

    # Create the premaster secret.
    premaster = mkword(version) + rand_str(length:46);

    # Encrypt the premaster secret with server's RSA public key.
    ckex = rsa_public_encrypt(data:premaster, n:n, e:e);

    # Encode the client key exchange data.
    #
    # It looks like TLS 1.0 and up prepend a two-byte length, but the
    # RFC is vague.
    if (_ssl['version'] >= TLS_10)
      ckex = ssl_vldata_put(data:ckex, len:2);
  }
  else if (_ssl['cipher_desc'] =~ "Kx=DH[(|]")
  {
    if (isnull(skex))
    {
      close(soc);
      return ssl3_set_error('Port ' + port + ': no ServerKeyExchange info (DH).');
    }

    # Generate the client private key,
    x = rand_str(length:16);

    # Compute g^x mod p.
    dh_x = bn_mod_exp(skex['dh_g'], x, skex['dh_p']);

    # Compute the premaster secret.
    premaster = bn_mod_exp(skex['dh_y'], x, skex['dh_p']);

    # Encode the client key exchange data.
    ckex = ssl_vldata_put(data:dh_x, len:2);
  }
  else if (_ssl['cipher_desc'] =~ "Kx=ECDH[(|]" && ecc_functions_available())
  {
    if (isnull(skex))
    {
      close(soc);
      return ssl3_set_error('Port ' + port + ': no ServerKeyExchange info (ECDH).');
    }

    # Generate the client private key
    dh_privkey = rand_str(length:16);

    # Compute the premaster secret
    premaster = ecc_scalar_multiply(
      curve_nid:curve_nid.tls[skex['named_curve']],
      scalar:dh_privkey,
      x:substr(skex['pubkey'], 1, (strlen(skex['pubkey'])) / 2),
      y:substr(skex['pubkey'], (strlen(skex['pubkey']) / 2) + 1)
    );
    # Just the X coordinate of the curve point is used
    premaster = ecc_fe2osp(element:premaster.x, curve_nid:curve_nid.tls[skex['named_curve']]);

    pubkey = ecc_scalar_multiply(
      curve_nid:curve_nid.tls[skex['named_curve']],
      scalar:dh_privkey
    );

    pubkey.x = ecc_fe2osp(element:pubkey.x, curve_nid:curve_nid.tls[skex['named_curve']]);
    pubkey.y = ecc_fe2osp(element:pubkey.y, curve_nid:curve_nid.tls[skex['named_curve']]);

    ckex = ssl_vldata_put(
      # Uncompressed curve point encoding
      data:'\x04' + pubkey.x + pubkey.y,
      len:1
    );
  }
  else
  {
    close(soc);
    return ssl3_set_error('Port ' + port + ': unsupported key exchange method ' + _ssl['cipher_desc'] + '.');
  }

  # Send an early ChangeCipherSpec message
  send(socket:soc, data:ssl_mk_record(type:SSL3_CONTENT_TYPE_CHANGECIPHERSPEC, data:mkbyte(1), version:version));

  # Check if the server responded to our early ChangeCipherSpec message. Vulnerable services do not.
  rec = recv_ssl(socket:soc, partial:TRUE);

  # Microsoft SSL services will close the connection with a TCP RST
  if (isnull(rec) && socket_get_error(soc) == ECONNRESET)
    return ssl3_set_error('Port ' + port + ': closed the connection when sent an early ChangeCipherSpec message.');

  # If we got something back, it might be an alert or it might be garbage
  if (!isnull(rec))
  {
    rec = ssl_find(
      blob:rec,
      'content_type', SSL3_CONTENT_TYPE_ALERT,
      'description',  SSL3_ALERT_TYPE_UNEXPECTED_MESSAGE,
      'level',        SSL3_ALERT_TYPE_FATAL
    );

    close(soc);

    if (!isnull(rec))
      return ssl3_set_error('Port ' + port + ': returned an SSL "unexpected message" alert when sent an early ChangeCipherSpec message.');
    else
      return ssl3_set_error('Port ' + port + ': responded to an early ChangeCipherSpec message, but not with an "unexpected message" alert.');
  }

  # Use an empty master secret for all MACs and encryption.
  empty_master = '';

  # Compute the 'real' master key. We need this when computing the Finished message
  real_master = ssl_calc_master(
    premaster : premaster,
    c_random  : clt_random,
    s_random  : srv_random,
    version   : version
  );

  keyblk = ssl_derive_keyblk(
    master   : empty_master,
    c_random : clt_random,
    s_random : srv_random,
    version  : version
  );

  if (!ssl3_set_keys(keyblk))
  {
    close(soc);
    return ssl3_set_error('Failed to set SSL keys.');
  }

  # Create a ClientKeyExchange message.
  msg = ssl_mk_handshake_msg(type:SSL3_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, data:ckex);
  hs += msg;

  # MAC and encrypt the ClientKeyExchange message (because we've sent an early CCS)
  msg += ssl3_mac(data:msg, type:SSL3_CONTENT_TYPE_HANDSHAKE);
  msg = ssl3_encrypt(msg);
  _ssl['clt_seq']++;

  pkt = ssl_mk_record(type:SSL3_CONTENT_TYPE_HANDSHAKE, data:msg, version:version);
  send(socket:soc, data:pkt);

  # Compute the Finished value for the client. All of the messages are encrypted/protected with the
  # empty master secret, but the Finished hash uses the correct master secret.
  clt_finished = ssl_calc_finished(master:real_master, handshake:hs, is_client:TRUE, version:version);
  msg = ssl_mk_handshake_msg(type:SSL3_HANDSHAKE_TYPE_FINISHED, data:clt_finished);
  hs += msg;

  # MAC and encrypt the ClientKeyExchange message (because we've sent an early CCS)
  msg += ssl3_mac(data:msg, type:SSL3_CONTENT_TYPE_HANDSHAKE);
  msg = ssl3_encrypt(msg);
  _ssl['clt_seq']++;

  pkt = ssl_mk_record(type:SSL3_CONTENT_TYPE_HANDSHAKE, data:msg, version:version);
  send(socket:soc, data:pkt);

  # Compute the Finished value for the server.
  #
  # The server has one more handshake message (the client's Finished)
  # to include when computing its Finished value.
  srv_finished = ssl_calc_finished(master:real_master, handshake:hs, is_client:FALSE, version:version);

  while (TRUE)
  {
    # Receive records from the server.
    recs = recv_ssl(socket:soc);
    if (isnull(recs))
    {
      close(soc);
      return ssl3_set_error('Port ' + port + ': server did not send the Finished message.');
    }

    rec = ssl_find(
      blob:recs,
      'content_type', SSL3_CONTENT_TYPE_ALERT
    );
    if (!isnull(rec)) return ssl3_set_error('Port ' + port + ': server returned an alert when sent messages encrypted with empty master secret.');

    # We are expecting a single encrypted record: the server's Finished.
    # It will be encrypted/MACed with the empty master secret, but its Finished hash will
    # use the correct master secret.
    rec = ssl_find(
      blob:recs,
      encrypted:TRUE,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE
    );
    if (isnull(rec)) continue;

    # Decrypt the record's body.
    plain = ssl3_decrypt(rec['data']);

    # Get the length of the padding.
    len = strlen(plain);
    padlen = getbyte(blob:plain, pos:len - 1);
    mac_size = strlen(_ssl['enc_mac_key']);
    # Check pad length
    if (padlen + 1 + mac_size > len)
    {
      close(soc);
      return ssl3_set_error('Port ' + port + ': invalid padlen '+padlen+'.');
    }

    # Check pad bytes for TLS 1.0
    # Each pad byte must be the same as the padlen, per TLS 1.0 RFC
    if(_ssl['version'] >= TLS_10)
    {
      for (i = 0; i < padlen; i++)
      {
        if(ord(plain[len - 2 -i]) != padlen)
        {
          close(soc);
          return ssl3_set_error('Port ' + port + ': invalid block cipher padding.');
        }
      }
    }

    # Extract the MAC.
    end = len - (padlen + 1) - 1;
    start = end - mac_size + 1;
    embedded_mac = substr(plain, start, end);

    # Extract the Finished record.
    end = start - 1;
    start = 0;
    msg =  substr(plain, start, end);

    # Extract the server's Finished value.
    #
    # Handshake message data starts after the 1-byte handshake type
    # and 3-byte handshake message length.
    embedded_srv_finished = substr(msg, 1 + 3);

    # Check the embedded MAC against ours.
    mac = ssl3_mac(data:msg, type:SSL3_CONTENT_TYPE_HANDSHAKE, client:FALSE);
    if (mac != embedded_mac)
    {
      close(soc);
      return ssl3_set_error('Port ' + port + ': MACs do not match, failed to decrypt server Finished message.');
    }

    # Check the embedded Finished value against ours.
    if (srv_finished != embedded_srv_finished)
    {
      close(soc);
      return ssl3_set_error('Port ' + port + ': bad server Finished message.');
    }

    # All tests have been passed, so the handshake phase is complete.
    break;
  }

  _ssl['sock'] = soc;
  _ssl['clt_seq']++;
  _ssl['srv_seq']++;

  close(soc);
  return TRUE;
}

##
# Initialize the SSL structure.
#
# @param port Port on which to make an SSL connection.
# @param cipher_list A list of cipher suite IDs to support.
# @param version The SSL version ID.
#
# @return TRUE if nothing went wrong.
##
function ssl3_init(port, cipher_list, version)
{
  local_var cipher, supported;

  # Check for the existence of some crypto functions.
  if (!defined_func('bn_mod_exp'))
  {
    return ssl3_set_error('function bn_mod_exp() not defined.');
  }
  if (!defined_func('rsa_public_encrypt'))
  {
    return ssl3_set_error('function rsa_public_encrypt() not defined.');
  }
  if (!defined_func('aes_cbc_encrypt'))
  {
    return ssl3_set_error('function aes_cbc_encrypt() not defined.');
  }
  if (!defined_func('aes_cbc_decrypt'))
  {
    return ssl3_set_error('function aes_cbc_decrypt() not defined.');
  }

  # Check SSL version.
  if (version != SSL_V3 && version != TLS_10)
  {
    return ssl3_set_error('SSL/TLS version ' + hexstr(mkword(version)) + ' is not supported.');
  }
  _ssl['version'] = version;

  # Check cipher suites.
  supported =
    ciphers['TLS1_CK_RSA_WITH_AES_256_CBC_SHA'] +
    ciphers['TLS1_CK_RSA_WITH_AES_128_CBC_SHA'] +
    ciphers['TLS1_CK_RSA_WITH_3DES_EDE_CBC_SHA'] +
    ciphers['TLS1_CK_DHE_RSA_WITH_AES_256_CBC_SHA'] +
    ciphers['TLS1_CK_DHE_RSA_WITH_AES_128_CBC_SHA'] +
    ciphers['TLS1_CK_DHE_RSA_WITH_3DES_EDE_CBC_SHA'] +
    ciphers['TLS1_CK_RSA_WITH_DES_CBC_SHA'] +
    ciphers['TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA'] +
    ciphers['TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA'];

  foreach cipher (cipher_list)
  {
    if (!ssl3_cipher_in_list(cipher, supported))
      return ssl3_set_error(FALSE, 'cipher suite ' + hexstr(cipher) + ' is not supported.');
  }

  # Initially set to a list of cipher suites supported by the client.
  # When ServerHello is received, it's set to the agreed cipher.
  _ssl['cipher'] = '';
  foreach cipher (cipher_list)
  {
    _ssl['cipher'] += cipher;
  }

  # Sequence number is incremented for each SSL record sent in each
  # direction. It's 64 bits long and used when computing the MAC of a
  # message. We use a 32-bit sequence number here as we don't expect
  # to use more than 2^32 records. When the 64-bit number is required
  # for certain operations, we just prepend 4 zero bytes in the front.
  _ssl['clt_seq'] = 0;
  _ssl['srv_seq'] = 0;

  # SSL uses big endian format.
  set_byte_order(BYTE_ORDER_BIG_ENDIAN);

  # Keep track of whether the mitigation techniques are seen.
  _ssl['empty_rec'] = FALSE;
  _ssl['one_byte_rec'] = FALSE;

  # Whether a certificate has been requested by the server.
  _ssl['clt_cert_req'] = FALSE;

  # Keep track of received, unprocessed application data.
  _ssl['app_data'] = '';

  # Number of application data records received
  _ssl['app_recs'] = 0;

  _ssl['port'] = port;

  return TRUE;
}

get_kb_item_or_exit('SSL/Supported');

# Get a port that uses SSL.
port = get_ssl_ports(fork:TRUE);

if (isnull(port))
  exit(1, 'The host does not appear to have any SSL-based services.');

# Find out if the port is open.
if (!get_port_state(port))
  audit(AUDIT_PORT_CLOSED, port, "TCP");

# Supported cipher suites used by this script.
cipher_list = make_list(
  ciphers['TLS1_CK_RSA_WITH_AES_256_CBC_SHA'],
  ciphers['TLS1_CK_RSA_WITH_AES_128_CBC_SHA'],
  ciphers['TLS1_CK_RSA_WITH_3DES_EDE_CBC_SHA'],
  ciphers['TLS1_CK_DHE_RSA_WITH_AES_256_CBC_SHA'],
  ciphers['TLS1_CK_DHE_RSA_WITH_AES_128_CBC_SHA'],
  ciphers['TLS1_CK_DHE_RSA_WITH_3DES_EDE_CBC_SHA'],
  ciphers['TLS1_CK_RSA_WITH_DES_CBC_SHA']
);

if (ecc_functions_available())
{
  cipher_list = make_list(
    cipher_list,
    ciphers['TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA'],
    ciphers['TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA']
  );
}

vulnerable = FALSE;
audit_message = '';

# Try SSLv3 first.
if (ssl3_init(port:port, version:SSL_V3, cipher_list:cipher_list))
  if (ssl3_connect())
    vulnerable = TRUE;

# If SSLv3 failed, for any reason (lack of support, simply not vulnerable)
# we will save the reason, and try TLSv1.
if (!vulnerable)
{
  audit_message += ssl3_get_lasterror();
  # Try TLSv1
  if (ssl3_init(port:port, version:TLS_10, cipher_list:cipher_list))
    if (ssl3_connect())
      vulnerable = TRUE;
}

if (!vulnerable)
{
  audit_message += " " + ssl3_get_lasterror();
  exit(1, audit_message);
}

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\nThe remote service on port ' + port + ' accepted an early ChangeCipherSpec message, which caused ' +
    '\nthe MAC and encryption keys to be derived entirely from public information. The entire SSL ' +
    '\nhandshake was completed, with the server accepting and producing messages encrypted and ' +
    '\nauthenticated using these weak keys.' +
    '\n';
}

set_kb_item(name:"SSL/earlyccs-1.0.1/" + port, value:"true");
security_hole(port:port, extra:report);
