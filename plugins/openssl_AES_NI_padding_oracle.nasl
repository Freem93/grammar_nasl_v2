#TRUSTED 6ac105faf2feeede140d7df8b30975d7f52b382fac42a2d8cd9a4b123ac73265000114a5f5d001c97813c545e987a071750c7e781c555be471bb34aa91dd87036c42c284d67a46e7205cfefec8695a239f7495ee4d9f395dd6d02e7f9c713886f224e61b4f89c3d303b065a0d576fb19a66bf1a9d1e313aad2c4367b10629bc2d78ecdf510938d18a21ecba5faf7fb623a2087637f27668b4406318ccee92dcb5d7c866094744c80737b6fab9a16902ae0a698276b5ad5db35c059fc7e0feb590bb5b4f77600577690747b93a5cff6404529061fe8b424913d0af5e8d358ceab11a380da9f4fa612e33ba7b2fc37e7631ae08e53c735099280ec02bb10e13a2af6b960be275633cf1ef5ef08b5e6ec7de2fef1225d2311687ddbbe2c67d3af87aec104471a5c7cf2275e0535fc15e46d0dd3d2f6070d52770d74875a0aeb88fa1009d19b2275cb79712529187f49cb0b044b80017d93f17993091bffb61f36ce45eacb30f129b3462a6cf225a41e7628a9cede0a13f46e4d8d0dcf69bdf26ecb9cf1df10caf97648d6f1cf9cdcaae453d4aca1b73e73a7c30bddff6e9656fe6aaad24a12962d7a0f0dbd1527d90bf45461c66819d6d90c4b43eb64f4ab53cc64ca88d3e33840cdbc9976d85eee0118eef742496cbf1ad582ac1993bddd3215dcc63e90694f611bbe2cf8b97b085e08f8cc02c3e5f38e683f5d2a85f903f429e2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91572);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/18");

  script_cve_id("CVE-2016-2107");
  script_bugtraq_id(89760);
  script_osvdb_id(137896);
  script_xref(name:"EDB-ID", value:"39768");

  script_name(english:"OpenSSL AES-NI Padding Oracle MitM Information Disclosure");
  script_summary(english:"Checks if the server sends a RECORD_OVERFLOW alert to a crafted TLS handshake.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain sensitive information from the remote host
with TLS-enabled services.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by a man-in-the-middle (MitM) information
disclosure vulnerability due to an error in the implementation of
ciphersuites that use AES in CBC mode with HMAC-SHA1 or HMAC-SHA256.
The implementation is specially written to use the AES acceleration
available in x86/amd64 processors (AES-NI). The error messages
returned by the server allow allow a man-in-the-middle attacker to
conduct a padding oracle attack, resulting in the ability to decrypt
network traffic.");
  script_set_attribute(attribute:"see_also", value:"https://blog.filippo.io/luckyminus20/");
  # https://web-in-security.blogspot.ca/2016/05/curious-padding-oracle-in-openssl-cve.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37b909b6");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160503.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.1t / 1.0.2h or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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
include("string.inc");

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
  local_var ckex, keyblk, tls_keys, tls_ciphertext, pubkey;

  # Get a socket to perform a handshake.
  soc = open_sock_ssl(port);
  if (!soc)
    # XXX-ALW Fix this error message
    return [FALSE, "open_sock_ssl", "Couldn't begin SSL handshake"];

  data = client_hello(
    v2hello:FALSE,
    version:mkword(TLS_10), # Record-layer version (RFC5246 Appendix E)
    maxver:mkword(TLS_12),  # Handshake version; maximum we support
    cipherspec:ciphers,
    extensions:tls_ext_ec(keys(curve_nid.tls))
  );
  send(socket:soc, data:data);
  rec = ssl_parse(blob:data);
  # Hang onto the Client Random; we need it to derive keys later.
  clt_random = mkdword(rec['time']) + rec['random'];

  # Read records one at a time. Expect to see at a minimum:
  # ServerHello, Certificate, and ServerHelloDone.
  while (TRUE)
  {
    # Receive a record from the server.
    data = recv_ssl(socket:soc);
    if (isnull(data))
    {
      close(soc);
      return [FALSE, "recv_ssl", "Did not receive expected ServerHello, ServerCertificate, etc."];
    }

    # ServerHello: Extract the random data for computation of keys.
    rec = ssl_find(
      blob:data,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
    );

    if (!isnull(rec))
    {
      # If server asks for version less than TLS 1.0 or higher than TLS 1.2, fail.
      if (rec['handshake_version'] < TLS_10 || rec['handshake_version'] > TLS_12)
        return [FALSE, "handshake_version", "Server does not support TLS 1.0, 1.1, or 1.2"];

      # Use the TLS version the server wants
      version = rec['handshake_version'];

      srv_random = mkdword(rec['time']) + rec['random'];

      # Wacko SSL servers might return a cipher suite not in the
      # client's request list.
      if (!tls_cipher_in_list(mkword(rec['cipher_spec']), ciphers))
      {
        close(soc);
        return [FALSE, "cipher_spec", "Server ignored our list of supported ciphers"];
      }

      # Store the negotiated cipher suite.
      cipher_desc = ciphers_desc[cipher_name(id:rec['cipher_spec'])];

      if (isnull(cipher_desc))
      {
        close(soc);
        return [FALSE, "cipher_spec", "Assertion failure"];
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
        return [FALSE, "parse_der_cert", "Failed to parse server's certificate"];
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
    data += ssl_mk_record(
      type:SSL3_CONTENT_TYPE_HANDSHAKE,
      version:version,
      data:ssl_mk_handshake_msg(
        type : SSL3_HANDSHAKE_TYPE_CERTIFICATE,
        data : ssl_vldata_put(data:NULL,len:3)
      )
    );
  }

  # Process ServerCertificate and ServerKeyExchange messages.
  if (cipher_desc =~ "Kx=RSA[(|]")
  {
    if (isnull(cert))
    {
      close(soc);
      return [FALSE, "rsa_kx", "Server selected RSA key exchange but didn't provide a certificate"];
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
      return [FALSE, "dh_kx", "Server selected DH key exchange but didn't provide a ServerKeyExchange"];
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
  else if (cipher_desc =~ "Kx=ECDH[(|]" && ecc_functions_available())
  {
    if (isnull(skex))
    {
      close(soc);
      return [FALSE, "ecdh_kx", "Server selected ECDHE key exchange but didn't provide a ServerKeyExchange"];
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
    return [FALSE, "kx", "Unsupported key exchange method"];
  }

  # Create a ClientKeyExchange record
  data += ssl_mk_record(
    type:SSL3_CONTENT_TYPE_HANDSHAKE,
    version:version,
    data:ssl_mk_handshake_msg(
      type:SSL3_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
      data:ckex
    )
  );

  tls_keys = tls_set_keys(
    cipher_desc:cipher_desc,
    keyblk:ssl_derive_keyblk(
      c_random:clt_random,
      s_random:srv_random,
      version:version,
      master:ssl_calc_master(
        c_random:clt_random,
        s_random:srv_random,
        version:version,
        premaster:premaster
      )
    )
  );

  if (tls_keys == FALSE)
  {
    close(soc);
    return [FALSE, "kx", "Failed to make TLS keys from key exchange"];
  }

  data += tls_mk_record(
    type:SSL3_CONTENT_TYPE_CHANGECIPHERSPEC,
    data:mkbyte(1),
    version:version
  );

  # Use a random IV, as it's included explicitly in TLS 1.1
  if (version >= TLS_11)
    tls_keys['enc_iv'] = rand_str(length:strlen(tls_keys['enc_iv']));

  # Finished message.
  # We make a record of just bad padding to trigger a RECORD_OVERFLOW alert.
  # 48 bytes of padding because:
  # o Must be a multiple of AES block size (16 bytes).
  # o Must be at least one byte bigger than the MAC size.
  # o SHA1 is 20 bytes, SHA256 is 32 bytes, so we round up to 48.
  # o SHA384 ciphersuites are not vulnerable.
  tls_ciphertext = aes_cbc_encrypt(
    data:crap(data:'\xff', length:48),
    iv:tls_keys['enc_iv'],
    key:tls_keys['enc_key']
  );
  # aes_cbc_encrypt() returns an array, [0] is ciphertext, [1] is CBC
  # residue (for TLS 1.0 IV). We don't retain the residue because we
  # don't intent to send any more records.
  tls_ciphertext = tls_ciphertext[0];

  # TLS 1.1 explicitly includes the IV in each record
  if (version >= TLS_11)
    tls_ciphertext = tls_keys['enc_iv'] + tls_ciphertext;

  data += tls_mk_record(
    type:SSL3_CONTENT_TYPE_HANDSHAKE,
    data:tls_ciphertext,
    version:version
  );

  # Send the ChangeCipherSpec and tampered Finished message
  send(socket:soc, data:data);

  while (TRUE)
  {
    # Receive a record from the server.
    data = recv_ssl(socket:soc);
    if (isnull(data))
    {
      close(soc);
      return [FALSE, "post_attack", "Server did not send an alert when sent a crafted Finished message"];
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
      if (rec['level'] == 2 && rec['description'] == SSL3_ALERT_TYPE_RECORD_OVERFLOW)
        return [TRUE, "post_attack", "Server sent RECORD_OVERFLOW alert"];
      else
        return [FALSE, "post_attack", "Server sent alert to tampered Finished. Level: " + rec['level'] + ", description: " + rec['description']];
    }
  }
}

get_kb_item_or_exit('SSL/Supported');

# Get a port that uses SSL.
port = get_ssl_ports(fork:TRUE);

if (isnull(port))
  exit(1, 'The host does not appear to have any SSL-based services.');

# Find out if the port is open.
if (!get_port_state(port))
  audit(AUDIT_PORT_CLOSED, port, "TCP");

# Ciphersuites should basically be the "Cartesian product" of:
# * DHE and RSA key exchanges
# * AES-CBC with 128- and 256-bit keys
# * SHA1 and SHA256 HMACs (SHA384 ciphersuites are not vulnerable)
# TODO: should support ECDHE and ECDSA, once we can do that from NASL.

# We test SHA1 separately from SHA256 and check if *either* was
# vulnerable, because vulnerable 1.0.1 servers support SHA256 but are
# only vulnerable on SHA1 ciphersuites. If we offered SHA1 and SHA256
# at the same time and the server preferred SHA256, it'd be a false
# negative.

cipher_list_sha1 =
  ciphers['TLS1_CK_RSA_WITH_AES_128_CBC_SHA'] + # <- Required by all TLS 1.2 impls.
  ciphers['TLS1_CK_RSA_WITH_AES_256_CBC_SHA'] +
  ciphers['TLS1_CK_DHE_RSA_WITH_AES_128_CBC_SHA'] +
  ciphers['TLS1_CK_DHE_RSA_WITH_AES_256_CBC_SHA'];

cipher_list_sha256 =
    ciphers['TLS1_RSA_WITH_AES_128_CBC_SHA256'] +
    ciphers['TLS1_RSA_WITH_AES_256_CBC_SHA256'] +
    ciphers['TLS1_DHE_RSA_WITH_AES_128_CBC_SHA256'] +
    ciphers['TLS1_DHE_RSA_WITH_AES_256_CBC_SHA256'];

if (ecc_functions_available())
{
  cipher_list_sha1 +=
    ciphers["TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA"] +
    ciphers["TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA"];

  cipher_list_sha256 +=
    ciphers["TLS1_ECDHE_RSA_WITH_AES_128_CBC_SHA256"] +
    ciphers["TLS1_ECDHE_RSA_WITH_AES_256_CBC_SHA256"];
}

sha1_result = attack(port:port, ciphers:cipher_list_sha1);

# Only do SHA256 test if we didn't find a vuln with SHA1.
if (sha1_result[0] == FALSE)
  sha256_result = attack(port:port, ciphers:cipher_list_sha256);

if (sha1_result[0] == TRUE || sha256_result[0] == TRUE)
{
  security_report_v4(
    port:port,
    severity:SECURITY_NOTE,
    extra:
      'Nessus was able to trigger a RECORD_OVERFLOW alert in the\n' +
      'remote service by sending a crafted SSL "Finished" message.'
  );
}
else
{
  exit(0,
    "[Port " + port + "] " +
    "SHA1 test: " + sha1_result[1] + ": " + sha1_result[2] + ". " +
    "SHA256 test: " + sha256_result[1] + ": " + sha256_result[2]);
}
