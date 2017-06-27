#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(27057);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_name(english:"Datagram Transport Layer Security Detection");
  script_summary(english:"Performs initial DTLS handshake");

  script_set_attribute(attribute:"synopsis", value:"An encrypted service is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service is encrypted using Datagram Transport Layer Security
(DTLS), which provides communications privacy for datagram protocols."
  );
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc4347");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  exit(0);
}


include("byte_func.inc");
include("misc_func.inc");
include("ssl_funcs.inc");


# nb: some UDP services are fragile so only run the plugin if
#     safe checks are disabled.
if (safe_checks()) exit(0);


set_byte_order(BYTE_ORDER_BIG_ENDIAN);

dtls_ver_10 = raw_string(0x01, 0x00);
ports = make_list(
  601,                                 # syslog (per draft-petch-gerhards-syslog-transport-dtls-00.txt)
  4433,                                # openssl s_server -dtls1 (default port)
  5061                                 # SIP (per draft-jennings-sip-dtls-05)
);


function dtls_client_hello(hlen, htype, ver, cipherspec, cspeclen, epoch, seqno, compmeths, compmethslen)
{
  local_var clen, frag_len, frag_ofs, handshake, hello;

  # Assign some defaults.
  # - handshake type.
  if (isnull(htype) || htype <= 0) htype = 1;  # client hello
  # - DTLS version.
  if (isnull(ver)) ver = dtls_ver_10;
  # - fragment offset.
  frag_ofs = 0;
  # - ciphers.
  if (isnull(cipherspec))
  {
    if (isnull(cspeclen))
      # nb: this is what openssl s_client uses by default.
      cipherspec =
        ciphers["TLS1_CK_DHE_RSA_WITH_AES_256_CBC_SHA"] +
        ciphers["TLS1_CK_DHE_DSS_WITH_AES_256_CBC_SHA"] +
        ciphers["TLS1_CK_RSA_WITH_AES_256_CBC_SHA"] +
        ciphers["TLS1_CK_DHE_RSA_WITH_3DES_EDE_CBC_SHA"] +
        ciphers["TLS1_CK_DHE_DSS_WITH_3DES_EDE_CBC_SHA"] +
        ciphers["TLS1_CK_RSA_WITH_3DES_EDE_CBC_SHA"] +
        ciphers["TLS1_CK_DHE_RSA_WITH_AES_128_CBC_SHA"] +
        ciphers["TLS1_CK_DHE_DSS_WITH_AES_128_CBC_SHA"] +
        ciphers["TLS1_CK_RSA_WITH_AES_128_CBC_SHA"] +
        ciphers["TLS1_CK_RSA_WITH_IDEA_CBC_SHA"] +
        ciphers["TLS1_CK_RSA_WITH_RC4_128_SHA"] +
        ciphers["TLS1_CK_RSA_WITH_RC4_128_MD5"] +
        ciphers["TLS1_CK_DHE_RSA_WITH_DES_CBC_SHA"]  +
        ciphers["TLS1_CK_DHE_DSS_WITH_DES_CBC_SHA"] +
        ciphers["TLS1_CK_RSA_WITH_DES_CBC_SHA"] +
        ciphers["TLS1_CK_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"] +
        ciphers["TLS1_CK_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"] +
        ciphers["TLS1_CK_RSA_EXPORT_WITH_DES40_CBC_SHA"] +
        ciphers["TLS1_CK_RSA_EXPORT_WITH_RC2_CBC_40_MD5"] +
        ciphers["TLS1_CK_RSA_EXPORT_WITH_RC4_40_MD5"];
    else
      # nb: fill it with random bytes.
      while (strlen(cipherspec) < cspeclen)
        cipherspec = cipherspec + (rand() % 256);
  }
  if (isnull(cspeclen))
  {
    cspeclen = strlen(cipherspec);
    cspeclen = raw_string(cspeclen / 256, cspeclen % 256);
  }
  # - epoch
  if (isnull(epoch)) epoch = 0;
  # - sequence number.
  if (isnull(seqno)) seqno = 0;
  # - compression methods
  if (isnull(compmeths)) {
    compmeths = raw_string(0x00);
    # nb: fill out field with random bytes.
    while (strlen(compmeths) < compmethslen)
      compmeths = compmeths + (rand() % 256);
  }
  if (isnull(compmethslen)) compmethslen = raw_string(strlen(compmeths));

  # Assemble the message.
  clen = 39 + strlen(cipherspec) + strlen(compmeths);
  frag_len = clen;

  handshake = mkbyte(htype) +          # handshake type
    mkbyte(clen / 0xff) +
      mkword(clen % 0xff) +
    mkword(seqno) +
    mkbyte(frag_ofs / 0xff) +
      mkword(frag_ofs % 0xff) +
    mkbyte(frag_len / 0xff) +
      mkword(frag_len % 0xff) +
    ver +
    mkdword(unixtime()) +
    crap(28) +
    mkbyte(0x00) +                     # session id length
    mkbyte(0x00) +                     # cookie length
    mkword(strlen(cipherspec)) +
    cipherspec +
    mkbyte(strlen(compmeths)) +
      compmeths;

  if (isnull(hlen)) hlen = strlen(handshake);
  hello = mkbyte(0x16) +                 # message type (0x16 => handshake)
    ver +
    mkword(epoch) +
    mkword(seqno / 0x10000) +
      mkdword(seqno % 0x10000) +
    mkword(hlen) +
      handshake;

  return(hello);
}


foreach port (ports)
{
  if (service_is_unknown(port:port, ipproto:"udp") && get_udp_port_state(port))
  {
    soc = open_sock_udp(port);
    if (soc)
    {
      hello = dtls_client_hello(seqno:0);
      send(socket:soc, data:hello);
      res = recv(socket:soc, length:8192, min:14);

      # If...
      if (
        # the response is long enough and...
        strlen(res) >= 13 &&
        # the reply uses our epoch and...
        getword(blob:res, pos:3) == epoch &&
        # the reply uses our sequence number and...
        (getword(blob:res, pos:5)*0x10000+getdword(blob:res, pos:7)) == seqno &&
        # the reply is either...
        (
          # a handshake verify request or...
          (getbyte(blob:res, pos:0) == 0x16 && getbyte(blob:res, pos:13) == 3) ||
          # an alert
          getbyte(blob:res, pos:0) == 0x15
        )
      )
      {
        # Complete the handshake so the connection can be reused.
        if (getbyte(blob:res, pos:0) == 0x16)
        {
          hello2 = dtls_client_hello(seqno:1);
          send(socket:soc, data:hello2);
          res2 = recv(socket:soc, length:8192, min:14);
          if (strlen(res2) >= 13  && getbyte(blob:res2, pos:13) == 2)
          {
            alert = mkbyte(0x15) +
              dtls_ver_10 +
              mkword(epoch) +
              mkword(0) + mkdword(2) +
              mkword(7) +
              mkbyte(2) +
              mkbyte(0x2a) +
              crap(5);
            send(socket:soc, data:alert);
            res3 = recv(socket:soc, length:14);
          }
        }

        # Report it.
        security_note(port:port, proto:"udp");
      }
      close(soc);
    }
  }
}
