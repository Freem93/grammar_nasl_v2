#TRUSTED 8c271d58851e6a139d7e008c1cae0a8c9cb815851b967a0d0d408511ff432fc836a9614809d681eab6400412a95dbbbef4915841992a93bd8ec8f69fdad85eb58b0c51d305a852bd98e307c9484734306a81184a5d6d8c6041e22c213368372f64daad5ff4e92fd9f1b5f6b7e47d7cea940d02ee4de0a28e3e0a64c618ebeccfe6991ee41f239fa7c461239226cef10b5ae49a2a473c4d3fa616703f30fe9bcc2bead5b6935bc86c71db8c1d7c1d108dc1e88877c7a0e2a50f63b314dd82a10d7929dc8adeaa57ca7c4783b03f8dfe0926e9fc030bfad8f220be31929f8ceccc8bd1c45ad9311e37fb0d79264be4dfb1dc0f6859a26eac824fc90c27ed3ca34aa81e3a70492ce89cc64740e99685c89797898df06fc787f8ff15907b4109dc807897755ce19d533076156a1e99ca6e0bca1967701839ab4d7ea345aa0527f77acfad85f33344c2b8600b40ea6e3a97222c1b0f84d448145a732120c04282c3fd1b1caac3692299eaf759635e0eafee2ba237549342992a12b4d163c6c4faba3427f36d34cb0c4414b391b821e31bc29e21ffa81d53cc4b7d950b02cc1c4d85a10a37790550def0d0b6387d7b329d34f5c1196059af2c1a8f7f36ebc3d8ad1ed44782bb7c8a484b9a05f3a7b9adda2a69bb3d6a978d6b03635f88d37a9d67d10209180a7476c3ef25887335894033b419a4482999e7845d2e1904242b6cdf45b1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58751);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/18");

  script_cve_id("CVE-2011-3389");
  script_bugtraq_id(49778);
  script_osvdb_id(74829);
  script_xref(name:"CERT", value:"864643");
  script_xref(name:"MSFT", value:"MS12-006");
  script_xref(name:"IAVB", value:"2012-B-0006");

  script_name(english:"SSL/TLS Protocol Initialization Vector Implementation Information Disclosure Vulnerability (BEAST)");
  script_summary(english:"Checks if SSL/TLS server uses empty or one-byte records.");

  script_set_attribute(attribute:"synopsis", value:
"It may be possible to obtain sensitive information from the remote
host with SSL/TLS-enabled services.");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in SSL 3.0 and TLS 1.0 that could allow
information disclosure if an attacker intercepts encrypted traffic
served from an affected system.

TLS 1.1, TLS 1.2, and all cipher suites that do not use CBC mode are
not affected.

This plugin tries to establish an SSL/TLS remote connection using an
affected SSL version and cipher suite and then solicits return data.
If returned application data is not fragmented with an empty or
one-byte record, it is likely vulnerable.

OpenSSL uses empty fragments as a countermeasure unless the
'SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS' option is specified when OpenSSL
is initialized.

Microsoft implemented one-byte fragments as a countermeasure, and the
setting can be controlled via the registry key
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\SendExtraRecord.

Therefore, if multiple applications use the same SSL/TLS
implementation, some may be vulnerable while others may not be,
depending on whether or not a countermeasure has been enabled.

Note that this plugin detects the vulnerability in the SSLv3/TLSv1
protocol implemented in the server. It does not detect the BEAST
attack where it exploits the vulnerability at HTTPS client-side
(i.e., Internet browser). The detection at server-side does not
necessarily mean your server is vulnerable to the BEAST attack,
because the attack exploits the vulnerability at the client-side, and
both SSL/TLS clients and servers can independently employ the split
record countermeasure.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"http://vnhacker.blogspot.com/2011/09/beast.html");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-006");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/2643584");
  script_set_attribute(attribute:"see_also", value:"http://blogs.msdn.com/b/kaushal/archive/2012/01/21/fixing-the-beast.aspx");
  script_set_attribute(attribute:"solution", value:
"Configure SSL/TLS servers to only use TLS 1.1 or TLS 1.2 if supported.
Configure SSL/TLS servers to only support cipher suites that do not
use block ciphers. Apply patches if available.

Note that additional configuration may be required after the
installation of the MS12-006 security update in order to enable the
split-record countermeasure. See Microsoft KB2643584 for details.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("acap_func.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("http.inc");
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

if (!get_kb_item("Settings/PCI_DSS") && !thorough_tests) exit(0, "This plugin only runs if 'Thorough tests' is enabled or if PCI scanning is enabled.");
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
  return _ssl['error'];
}

##
# Write data from an established SSL connection.
#
# @anonparam data Data to be written.
#
# @return TRUE for success, FALSE otherwise.
##
function ssl3_write()
{
  local_var data, dlen, mac, rec, rlen, sent, type;

  data = _FCT_ANON_ARGS[0];

  type = SSL3_CONTENT_TYPE_APPLICATION_DATA;
  dlen = strlen(data);

  # Compute the MAC of the unencrypted application data.
  mac = ssl3_mac(data:data, type:type);

  # Append the MAC to the data and encrypt everything.
  data = ssl3_encrypt(data + mac);

  # Make a record and send it to the server.
  rec = ssl_mk_record(type:type, data:data, version:_ssl['version']);
  rlen = strlen(rec);
  sent = send(socket:_ssl['sock'], data:rec);
  if (sent != rlen)
    return ssl3_set_error('ssl3_write(): Only sent ' + sent + ' of ' + rlen + ' bytes to port ' + _ssl['port'] + '.');

  _ssl['clt_seq']++;

  return dlen;
}

##
# Read data from an established SSL connection.
#
# @param len Number of bytes to be read.
#
# @return Data read, or NULL if there is an error.
##
function ssl3_read(len)
{
  local_var computed_mac, data, dlen, embedded_mac, end, i, maclen;
  local_var msg, padlen, rec, srv_seq, start, timeout;

  # Return data can be split into multiple records.
  while (TRUE)
  {
    # Check if we have received enough received data to satisfy the
    # caller.
    if (len && strlen(_ssl['app_data']) >= len)
    {
      # Remove the requested amount of data from the receive buffer.
      data = substr(_ssl['app_data'], 0, len - 1);
      _ssl['app_data'] -= data;

      return data;
    }

    # Receive an SSL message.
    # Some Microsoft Exchange servers take many seconds to reply to an
    # SMTP command, causing this check to false-negative.
    # Obey a longer read timeout, but make 15 seconds the minimum to
    # cope with these servers.
    timeout = get_read_timeout();
    if (timeout < 15)
      timeout = 15;
    msg = recv_ssl(socket:_ssl['sock'], timeout:timeout);
    if (isnull(msg)) break;

    # Parse the message, keeping in mind that the body is encrypted.
    rec = ssl_parse(blob:msg, encrypted:TRUE);
    if (isnull(rec))
      return ssl3_set_error('ssl3_read(): Failed to parse encrypted SSL record.');

    # Check protocol version.
    if (rec['version'] != _ssl['version'])
      return ssl3_set_error('ssl3_read(): SSL/TLS protocol version mismatch.');

    # Ensure that the record isn't an alert.
    if (rec['content_type'] == SSL3_CONTENT_TYPE_ALERT)
      return ssl3_set_error('ssl3_read(): Alert received from port ' + _ssl['port'] + '.');

    # Decrypt the application data.
    data = ssl3_decrypt(rec['data']);
    dlen = strlen(data);

    # Check that padding on the data is sane.
    maclen = strlen(_ssl['enc_mac_key']);
    padlen = getbyte(blob:data, pos:dlen - 1);
    if (padlen + 1 + maclen > dlen)
      return ssl3_set_error('ssl3_read(): invalid padlen ' + padlen + '.');

    # Check pad bytes for TLS 1.0
    # For SSL 3.0, pad bytes can have arbitrary values
    # For TLS 1.0, each pad byte must be same as padlen
    if (_ssl['version'] >= TLS_10)
    {
      for (i = 0; i < padlen; i++)
      {
        if(ord(data[dlen - 2 -i]) != padlen)
          return ssl3_set_error('ssl3_read(): invalid block cipher padding.');
      }
    }

    # Extract the MAC, which is appended to the payload.
    end = dlen - (padlen + 1) - 1;
    start = end - maclen + 1;
    embedded_mac = substr(data, start, end);

    # Extract decrypted application data.
    end = start - 1;
    start = 0;
    data = substr(data, start, end);


    # Compute the MAC of the decrypted application data.
    computed_mac = ssl3_mac(data:data, type:rec['content_type'], client:FALSE);

    # Compare the embedded MAC and the computed MAC.
    if (computed_mac != embedded_mac)
      return ssl3_set_error('ssl3_read(): MACs do not match.');

    # The MAC was proper, so this packet is accepted.
    _ssl['srv_seq']++;

    # Add application data to our receive buffer.
    if (rec['content_type'] == SSL3_CONTENT_TYPE_APPLICATION_DATA)
    {
      _ssl['app_data'] += data;
      _ssl['app_recs'] += 1;


      # Check for mitigation techniques:
      # - Empty records: OpenSSL uses this technique if
      #   SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS is not set.
      # - One-byte records: Microsoft uses this technique.
      #
      # Check for split-record for the first 2 app data records
      if(_ssl['app_recs'] < 3)
      {
        if (isnull(data))
          _ssl['empty_rec'] = TRUE;
        else if (strlen(data) == 1)
          _ssl['one_byte_rec'] = TRUE;
      }
    }
  }

  # If the read length could not be satisfied, return whatever is in
  # the receive buffer, and clear it for future calls.
  data = _ssl['app_data'];
  _ssl['app_data'] = '';

  if (empty_or_null(data) && socket_get_error(_ssl['sock']) == ETIMEDOUT)
    return ssl3_set_error('ssl3_read(): Server did not reply after waiting ' + timeout + ' seconds. Consider increasing the read timeout in your scan policy.');

  return data;
}

##
# Disconnect from the SSL server.
##
function ssl3_disconnect()
{
  close(_ssl['sock']);
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
  local_var master, msg, n, padlen, parsed, pkt, plain, port;
  local_var premaster, rec, recs, skex, soc, srv_finished, srv_random;
  local_var start, version, x;

  # Get a socket to perform a handshake.
  port = _ssl['port'];
  soc = open_sock_ssl(port);
  if (!soc)
    return ssl3_set_error('ssl3_connect(): Failed to connect to port ' + port + '.');

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
      return ssl3_set_error('ssl3_connect() on port ' + port + ': server did not respond to ClientHello.');
    }

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
        return ssl3_set_error('ssl3_connect() on port ' + port + ': SSL/TLS protocol version mismatch.');
      }

      srv_random = mkdword(rec['time']) + rec['random'];

      # Wacko SSL servers might return a cipher suite not in the
      # client's request list.
      if (!ssl3_cipher_in_list(mkword(rec['cipher_spec']), _ssl['cipher']))
      {
        close(soc);
        return ssl3_set_error('ssl3_connect() on port ' + port + ': server returned a cipher suite not in list supported by client.');
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
        return ssl3_set_error('ssl3_connect() on port ' + port + ': server certificate could not be parsed.');
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
      return ssl3_set_error('ssl3_connect() on port ' + port + ': No server certificate was found.');
    }

    if (isnull(cert['subjectPublicKeyInfo']) || isnull(cert['subjectPublicKeyInfo'][1]))
    {
      close(soc);
      return ssl3_set_error('ssl3_connect() on port ' + port + ': A server certificate with an unsupported algorithm was found.');
    }

    n = cert['subjectPublicKeyInfo'][1][0];
    e = cert['subjectPublicKeyInfo'][1][1];
    if(isnull(n) || isnull(e))
    {
      close(soc);
      return ssl3_set_error('ssl3_connect() on port ' + port + ': Failed to extract public key from server certificate.');
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
      return ssl3_set_error('ssl3_connect() on port ' + port + ': no ServerKeyExchange info (DH).');
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
      return ssl3_set_error('ssl3_connect() on port ' + port + ': no ServerKeyExchange info (ECDH).');
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

    # Encode the client's DH public key
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
    return ssl3_set_error('ssl3_connect() on port ' + port + ': unsupported key exchange method ' + _ssl['cipher_desc'] + '.');
  }

  # Create a ClientKeyExchange message.
  msg = ssl_mk_handshake_msg(type:SSL3_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, data:ckex);
  hs += msg;

  rec = ssl_mk_record(type:SSL3_CONTENT_TYPE_HANDSHAKE, data:msg, version:version);
  pkt += rec;

  # Compute the keys.
  master = ssl_calc_master(
    premaster : premaster,
    c_random  : clt_random,
    s_random  : srv_random,
    version   : version
  );

  # For troubleshooting problems, when a PCAP is provided by a customer
  # and we need to see the encrypted application data records.
  set_kb_item(
    name:"nss_keylog/" + SCRIPT_NAME,
    value:"CLIENT_RANDOM " + hexstr(clt_random) + " " + hexstr(master)
  );

  keyblk = ssl_derive_keyblk(
    master   : master,
    c_random : clt_random,
    s_random : srv_random,
    version  : version
  );

  if (!ssl3_set_keys(keyblk))
  {
    close(soc);
    return ssl3_set_error('ssl3_connect(): ssl3_set_keys() failed.');
  }

  # Compute the Finished value for the client.
  clt_finished = ssl_calc_finished(master:master, handshake:hs, is_client:TRUE, version:version);
  msg = ssl_mk_handshake_msg(type:SSL3_HANDSHAKE_TYPE_FINISHED, data:clt_finished);

  # Compute the Finished value for the server.
  #
  # The server has one more handshake message (the client's Finished)
  # to include when computing its Finished value.
  hs += msg;
  srv_finished = ssl_calc_finished(master:master, handshake:hs, is_client:FALSE, version:version);

  # Compute the HMAC of the Finished message for the client.
  mac = ssl3_mac(data:msg, type:SSL3_CONTENT_TYPE_HANDSHAKE);

  # Append the HMAC to the message.
  msg += mac;

  # Encrypt the client Finished message
  msg = ssl3_encrypt(msg);

  # Append the ChangeCipherSpec and Finished records to the packet.
  pkt += ssl_mk_record(type:SSL3_CONTENT_TYPE_CHANGECIPHERSPEC, data:mkbyte(1), version:version);
  pkt += ssl_mk_record(type:SSL3_CONTENT_TYPE_HANDSHAKE, data:msg, version:version);

  # Send the packet.
  send(socket:soc, data:pkt);

  while (TRUE)
  {
    # Receive records from the server.
    recs = recv_ssl(socket:soc);
    if (isnull(recs))
    {
      close(soc);
      return ssl3_set_error('ssl3_connect() on port ' + port + ': server did not send the Finished message.');
    }

    # Finished, but it's encrypted so we can't access the handshake
    # type with ssl_parse().
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
      return ssl3_set_error('ssl3_connect() on port ' + port + ': invalid padlen '+padlen+'.');
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
          return ssl3_set_error('ssl3_connect() on port ' + port + ': invalid block cipher padding.');
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
      return ssl3_set_error('ssl3_connect() on port ' + port + ': MACs do not match, failed to decrypt server Finished message.');
    }

    # Check the embedded Finished value against ours.
    if (srv_finished != embedded_srv_finished)
    {
      close(soc);
      return ssl3_set_error('ssl3_connect() on port ' + port + ': bad server Finished message.');
    }

    # All tests have been passed, so the handshake phase is complete.
    break;
  }

  _ssl['sock'] = soc;
  _ssl['clt_seq']++;
  _ssl['srv_seq']++;

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
    ciphers['TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA'] +
    ciphers['TLS1_CK_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA'];

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
  audit(AUDIT_PORT_CLOSED, port);

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
  # This list will be flattened on its own by make_list().
  cipher_list = make_list(
    cipher_list,
    ciphers['TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA'],
    ciphers['TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA'],
    ciphers['TLS1_CK_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA']
  );
}


# Try TLS 1.0 first.
if (!ssl3_init(port:port, version:TLS_10, cipher_list:cipher_list))
  exit(1, 'ssl3_init() failed on port ' + port + ': ' + ssl3_get_lasterror());

# If that failed, try SSL 3.0.
if (!ssl3_connect())
{
  if (!ssl3_init(port:port, version:SSL_V3, cipher_list:cipher_list))
    exit(1, 'ssl3_init() failed on port ' + port + ': ' + ssl3_get_lasterror());

  if (!ssl3_connect()) exit(1, ssl3_get_lasterror());
}

# Send some data to the SSL port so that some data can be returned in
# order to test whether empty or one-byte records are used.

# Create a simple HTTP GET request.
http_req = http_mk_req(port:port, host:get_host_ip(), method:'GET', item:'/', add_headers:make_array('Connection','keep-alive'));

svc = known_service(port:port);

# Create a service-specific message to solicit a response in order to
# test for an empty or one-byte record.
if (svc == 'www') req = http_mk_buffer_from_req(req:http_req);
else if (svc == 'smtp')   req = 'EHLO client.example.org\r\n';
else if (svc == 'ftp')    req = 'HELP\r\n';
else if (svc == 'ldap')   req = ldap_bind_request();
else if (svc == 'imap')   req = 'nessus CAPABILITY\r\n';

# The following are not tested.
else if (svc == 'pop3')   req = 'CAPA\r\n';
else if (svc == 'nntp')   req = 'CAPABILITIES\r\n';
else if (svc == 'acap')   req = 'nessus NOOP\r\n';
else if (svc == 'xmpp')   req = '<nessus />\n';
else if (svc == 'telnet') req = mkbyte(CMD_IAC) + mkbyte(CMD_DO) + mkbyte(5); # Do Status

# Unknown service, send an HTTP request.
else req = http_mk_buffer_from_req(req:http_req);

#
# Read at least 2 application data records
#
# The fix for BEAST in IBMJSSE2 is to split the application data record to
# 1/(n-1), except the first application data record.
# So we need the second application data record to test whether it is split.
#
while(_ssl['app_recs'] < 2)
{

  # Send the request.
  if (!ssl3_write(req))
    exit(1, ssl3_get_lasterror());

  # Read until no more application data from remote server
  data = ssl3_read();

  # Check response.
  if (isnull(data)) exit(1, ssl3_get_lasterror());
  if( data == '')   exit(0, 'The service listening on port ' + port + ' did not return any data.');

  # 0/n split-record mitigation technique (OpenSSL)
  if (_ssl['empty_rec'])
    exit(0, 'The service listening on port ' + port + ' appears to use empty SSL/TLS records.');

  # 1/(n-1) split-record mitigation technique (MS)
  if (_ssl['one_byte_rec'])
    exit(0, 'The service listening on port ' + port + ' appears to use one-byte SSL/TLS records.');

}

# The SSL 3.0/TLS 1.0 server accepts a block-based cipher suite, but
# doesn't use any mitigation techniques, so it is likely vulnerable.
if (report_verbosity > 0)
  security_warning(port:port, extra:'\nNegotiated cipher suite: ' + _ssl['cipher_desc'] + '\n');
else
  security_warning(port);
