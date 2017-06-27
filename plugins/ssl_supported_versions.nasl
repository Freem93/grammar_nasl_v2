#TRUSTED 16c55689d2b8d381a4ba5ec638d1e0cdbb69747de964a22b53124562b3686e80883f7c50ca7eb5442c26c5df7939793a74744639b3158f1301c6e416324ea5ddf07685f7f005729d5a8c7a10c50eb95328d09cfecc64829751af3fc7a41901bea9a8830cf51a5a46f08957e3e4ba9567525fa69c896b2c84de191e3dce44a3d5ef537fa124c220f2abd235220f15eb0996b82fab296f7ec42c2455585856ed8bd2711fe2bdd58e9707a09baf9b9a1d35f249d5807abf85cc660c0b1776740f0c49e18ef4eb8cd5deb441c919c01e7c3008473e1ae79744de8975f991ce3fb78e10ea1f9111efd4b69f47b518207d3f00779b39c4ef36a5ef1cec83767ddeccb885a5719bfc62dc3a418f1602e825abbc6b72f14e664cc6c22a9c218f6ffa2ccf82c17d098ce17593c14358eea3f24799f318a9171b88a38d2ce27c45c64cf7c98302c18fb8e327d118e7ee1005953932c3aa7f4cddc192223d1f279e12c42fb5a9de46bcd458c3739cc45f8fd87670fc8a4b9c3740fa235c511a1b77ff625f2e5f4d0bc4f3b156afc1c90349cf2a349c5c09bd89d51d12a34e4af5b1040a3b115646e82dac4efd326ce1847ab5057c1ab9d6b445649f348ae7b1e54ff11ee15f24ba6027177d329e43ee93f450e14152ad5e7283520d80e5976edaf7fd5da37f383232a0c61adcf69d1f65321f35af30f0206ddad9b5a63935acf0d8225d0c1f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56984);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/01/11");

  script_name(english:"SSL / TLS Versions Supported");
  script_summary(english:"Checks which SSL / TLS versions are supported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service encrypts communications.");
  script_set_attribute(attribute:"description", value:
"This plugin detects which SSL and TLS versions are supported by the
remote service for encrypting communications.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "apache_SSL_complain.nasl");
  if (NASL_LEVEL >= 3000)
    script_dependencies(
      "acap_starttls.nasl",
      "amqp_starttls.nasl",
      "ftp_starttls.nasl",
      "imap4_starttls.nasl",
      "ldap_starttls.nasl",
      "mssql_starttls.nasl",
      "nntp_starttls.nasl",
      "nut_starttls.nasl",
      "pop3_starttls.nasl",
      "rdp_ssl.nasl",
      "smtp_starttls.nasl",
      "telnet_starttls.nasl",
      "xmpp_starttls.nasl",
      "ircd_starttls.nasl",
      "rsync_starttls.nasl"
    );

  exit(0);
}

include("byte_func.inc");
include("acap_func.inc");
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
include("rsync.inc");

global_var openssl_ciphers;

if ( get_kb_item("global_settings/disable_ssl_cipher_neg" ) ) exit(1, "Not negotiating the SSL ciphers, per user config");

openssl_ciphers = make_array(
  "SSLv2", raw_string(
    0x07, 0x00, 0xc0,
    0x05, 0x00, 0x80,
    0x03, 0x00, 0x80,
    0x01, 0x00, 0x80,
    0x06, 0x00, 0x40,
    0x04, 0x00, 0x80,
    0x02, 0x00, 0x80
  ),
  "SSLv23", raw_string(
    0x00, 0x00, 0x89,
    0x00, 0x00, 0x88,
    0x00, 0x00, 0x87,
    0x00, 0x00, 0x84,
    0x00, 0x00, 0x46,
    0x00, 0x00, 0x45,
    0x00, 0x00, 0x44,
    0x00, 0x00, 0x41,
    0x00, 0x00, 0x3a,
    0x00, 0x00, 0x39,
    0x00, 0x00, 0x38,
    0x00, 0x00, 0x35,
    0x00, 0x00, 0x34,
    0x00, 0x00, 0x33,
    0x00, 0x00, 0x32,
    0x00, 0x00, 0x2f,
    0x00, 0x00, 0x1b,
    0x00, 0x00, 0x1a,
    0x00, 0x00, 0x19,
    0x00, 0x00, 0x18,
    0x00, 0x00, 0x17,
    0x00, 0x00, 0x16,
    0x00, 0x00, 0x15,
    0x00, 0x00, 0x14,
    0x00, 0x00, 0x13,
    0x00, 0x00, 0x12,
    0x00, 0x00, 0x11,
    0x00, 0x00, 0x0a,
    0x00, 0x00, 0x09,
    0x00, 0x00, 0x08,
    0x00, 0x00, 0x06,
    0x00, 0x00, 0x05,
    0x00, 0x00, 0x04,
    0x00, 0x00, 0x03,
    0x07, 0x00, 0xc0,
    0x06, 0x00, 0x40,
    0x04, 0x00, 0x80,
    0x03, 0x00, 0x80,
    0x02, 0x00, 0x80,
    0x01, 0x00, 0x80,
    0x00, 0x00, 0xff
  ),
  "TLSv1", raw_string(
    0xc0, 0x14,
    0xc0, 0x0a,
    0x00, 0x39,
    0x00, 0x38,
    0x00, 0x88,
    0x00, 0x87,
    0xc0, 0x0f,
    0xc0, 0x05,
    0x00, 0x35,
    0x00, 0x84,
    0xc0, 0x12,
    0xc0, 0x08,
    0x00, 0x16,
    0x00, 0x13,
    0xc0, 0x0d,
    0xc0, 0x03,
    0x00, 0x0a,
    0xc0, 0x13,
    0xc0, 0x09,
    0x00, 0x33,
    0x00, 0x32,
    0x00, 0x9a,
    0x00, 0x99,
    0x00, 0x45,
    0x00, 0x44,
    0xc0, 0x0e,
    0xc0, 0x04,
    0x00, 0x2f,
    0x00, 0x96,
    0x00, 0x41,
    0x00, 0x07,
    0xc0, 0x11,
    0xc0, 0x07,
    0xc0, 0x0c,
    0xc0, 0x02,
    0x00, 0x05,
    0x00, 0x04,
    0x00, 0x15,
    0x00, 0x12,
    0x00, 0x09,
    0x00, 0x14,
    0x00, 0x11,
    0x00, 0x08,
    0x00, 0x06,
    0x00, 0x03,
    0x00, 0xff
  )
);

function supports(encaps, port)
{
  local_var cipher, cipherspec, helo, i, limit, rec, recs, sock, v2;
  local_var version, exts, exts_len;

  # Both SSLv2 and SSLv23 clients begin by sending an record in SSLv2
  # format.
  v2 = (encaps == ENCAPS_SSLv2 || encaps == ENCAPS_SSLv23);

  if (encaps == ENCAPS_SSLv2) version = raw_string(0x00, 0x02);
  else if (encaps == ENCAPS_SSLv3) version = raw_string(0x03, 0x00);
  else if (encaps == ENCAPS_TLSv1) version = raw_string(0x03, 0x01);
  else if (encaps == COMPAT_ENCAPS_TLSv11) version = raw_string(0x03, 0x02);
  else if (encaps == COMPAT_ENCAPS_TLSv12) version = raw_string(0x03, 0x03);

  # For most encapsulation types we first try connecting with all
  # ciphers, and then try with a OpenSSL's default set. For SSLv23 we
  # need an extra iteration since trying all ciphers needs to be done
  # in both SSLv3 and TLSv1 upgrade modes to detect all server
  # configurations.
  limit = 2;
  if (encaps == ENCAPS_SSLv23)
    limit += 1;

  for (i = 1; i <= limit; i++)
  {
    # SSLv23 goes through the following phases:
    #
    # 1) SSLv2 upgradeable to SSLv3 with all known ciphers.
    # 2) SSLv2 upgradeable to TLSv1 with all known ciphers.
    # 3) SSLv2 upgradeable to TLSv1 with OpenSSL's default ciphers.
    if (encaps == ENCAPS_SSLv23)
    {
      if (i == 1)
        version = raw_string(0x03, 0x00);
      else
        version = raw_string(0x03, 0x01);
    }

    if (i != limit)
    {
      # See if the server supports this type of SSL by sending a
      # ClientHello with every possible cipher spec.
      cipherspec = "";
      foreach cipher (sort(keys(ciphers)))
      {
        if (
          (encaps == ENCAPS_SSLv2 && "SSL2_" >< cipher) ||
          (
            encaps == ENCAPS_SSLv23 &&
            (
              "SSL2_" >< cipher ||
              (i == 0 && "SSL3_" >< cipher) ||
              (i == 1 && "TLS1_" >< cipher)
            )
          ) ||
          # ciphers for >=SSLv3
          (
            encaps >= ENCAPS_SSLv3 &&
            encaps <= COMPAT_ENCAPS_TLSv12 &&
            strlen(ciphers[cipher]) == 2
          )
        )
        {
          # Normally, we can just add the cipher to the cipherspec,
          # but in SSLv23 we have to zero-extend the SSLv3 and TLSv1
          # ciphers to match the SSLv2 format.
          if (encaps == ENCAPS_SSLv23 && "SSL2_" >!< cipher)
            cipherspec += raw_string(0x00);
          cipherspec += ciphers[cipher];
        }
      }
    }
    else
    {
      # Certain SSL implementations, when sent a ClientHello with a
      # number of ciphers past some threshold, simply close the
      # socket. If we see this, try connecting with the default list
      # that OpenSSL uses.
      if (encaps == ENCAPS_SSLv2)
        cipherspec = openssl_ciphers["SSLv2"];
      else if (encaps == ENCAPS_SSLv23)
        cipherspec = openssl_ciphers["SSLv23"];
      else if (encaps >= ENCAPS_SSLv3 && encaps <= COMPAT_ENCAPS_TLSv12)
        cipherspec = openssl_ciphers["TLSv1"];
    }


    # In some SSL implementations, EC-based cipher suites require
    # a supported named curve in ClientHello for it to return a
    # ServerHello, so we will send EC extensions, claiming
    # to support all curves and EC point formats.
    if (encaps >= ENCAPS_TLSv1 && encaps <= COMPAT_ENCAPS_TLSv12)
    {
      exts = tls_ext_ec() + tls_ext_ec_pt_fmt();

      if(encaps == COMPAT_ENCAPS_TLSv12)
        exts += tls_ext_sig_algs();

      exts_len  = mkword(strlen(exts));
    }
    else exts = exts_len = NULL;

    # Manually craft a ClientHello.
    rec = client_hello(
      version    : version,
      cipherspec : cipherspec,
      v2hello    : v2,
      extensions: exts,
      extensionslen: exts_len
    );
    if (isnull(rec)) return FALSE;

    # Open a connection to the server.
    sock = open_sock_ssl(port);
    if (!sock) return FALSE;

    # Send the ClientHello.
    send(socket:sock, data:rec);

    # Receive target's response.
    recs = "";
    repeat
    {
      rec = recv_ssl(socket:sock, timeout:20);
      if (isnull(rec)) break;
      recs += rec;
    } until (!socket_pending(sock));
    close(sock);

    # Find the ServerHello record.
    if (encaps == ENCAPS_SSLv2)
    {
      rec = ssl_find(
        blob:recs,
        "content_type", SSL2_CONTENT_TYPE_SERVER_HELLO
      );
    }
    else
    {
      rec = ssl_find(
        blob:recs,
        "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
        "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
      );
    }

    # If we didn't find the record we were looking for, then the
    # server doesn't support this encapsulation method.
    if (isnull(rec)) continue;

    # If we're in SSLv2 mode, we'd like an SSLv2 response. If we're in
    # any other mode, success is indicated by an SSLv3/TLSv1 response
    # with a version number matching our ClientHello.
    if (rec["version"] == getword(blob:version, pos:0))
      return TRUE;
  }

  return FALSE;
}

# All parameters in SSL are big-endian.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Get list of ports that use SSL or StartTLS.
ports = get_ssl_ports();
if (isnull(ports) || max_index(ports) == 0)
  exit(0, "The host does not appear to have any SSL-based services.");

encapsulations = make_array(
  "SSLv2", ENCAPS_SSLv2,
#  "SSLv23", ENCAPS_SSLv23, # XXX-MAK: Disabled due to FPs.
  "SSLv3", ENCAPS_SSLv3,
  "TLSv1.0", ENCAPS_TLSv1,
  "TLSv1.1", COMPAT_ENCAPS_TLSv11,
  "TLSv1.2", COMPAT_ENCAPS_TLSv12
);

# Test every port for which versions of SSL/TLS are supported.
flag = 0;
foreach port (ports)
{
  if (!get_port_state(port)) continue;

  versions = make_list();

  # Check each version of SSL/TLS.
  foreach encaps (sort(keys(encapsulations)))
  {
    id = encapsulations[encaps];

    if (!supports(port:port, encaps:id)) continue;

    versions = make_list(versions, encaps);

    set_kb_item(name:"SSL/Transport/" + port, value:id);
  }

  # Combine results from all versions into one report for this port.
  if (max_index(versions) == 0) continue;

  if ( flag == 0 )
  {
	set_kb_item(name:"SSL/Supported", value:TRUE);
	flag = 1;
  }

  report = '\nThis port supports ' + join(versions, sep:"/") + '.\n';
  security_note(port:port, extra:report);
}
