#TRUSTED 4750aafc4748b78c4188b1687e98036639838472dc5404c478f8b1e71ebfe2212ff09823b038929e8e10ec8e462b34cebfbb3968fcbe17b3ba06b12147f95fd766739da949c4579c478508e788046921cb558cb9112f055b684b86b1068b99aa2610622b9c7b754c81241b8a22bfc594d86d1e62464831280d0e433ba4ff5063e4e463fdb97ac3bd219827174a80171b5c28b09f8f49d8e87a86104db03a0728efed6637478f70cb06054d7a29ed5b9a45db01a5448b07e92dbeb2def98cedde5844677bf90b28e53e8d07751f6f62f0a5d504f702ce7e9403ab8ad519aa0f0b8c6d7025a67fff13cc9276a4d3c98d8ae0aa2e34a71053768bccb32ce6a0ead55e944351decf95959e9f1d8b93f12bea99328c22bdd2b6419ff885f13ad3a01c5c0a982cd6702285a8d9d6062a2b3b9fe7f0fb7ab6d8994b2841653e62928fe5446e110eea57ded3bbdfce8479840226914f495468c8069dd4c8539653f021db4d8447ef427f1a2203a6d031f7267eae101dabf234bc7673963e4b926d1f7a185f69b44e4d1849dd36614f8142b71cff9900d5c6b5b38a85892eafe9e49418d89fadb87ad826faafa69c4aee9243b7bb794ebe9170dcf2b1461754d1cf544cb7e73b3b6b5acceea28e3bfe3d4fabe8902f3aa285b9e94da5e20a80f2b0a92ddc8faa98bbf23be65ac37a5b873159e745ef0df3fe9123553c14be036e9c7140ec
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83875);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/06/16");

  script_cve_id("CVE-2015-4000");
  script_bugtraq_id(74733);
  script_osvdb_id(122331);

  script_name(english:"SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)");
  script_summary(english:"Checks to see what DH modulus sizes are being used.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host allows SSL/TLS connections with one or more
Diffie-Hellman moduli less than or equal to 1024 bits."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host allows SSL/TLS connections with one or more
Diffie-Hellman moduli less than or equal to 1024 bits. Through
cryptanalysis, a third party may be able to find the shared secret in
a short amount of time (depending on modulus size and attacker
resources). This may allow an attacker to recover the plaintext or
potentially violate the integrity of connections."
  );
  script_set_attribute(attribute:"see_also",value:"http://weakdh.org/");
  script_set_attribute(
    attribute:"solution",
    value:
"Reconfigure the service to use a unique Diffie-Hellman moduli of 2048
bits or greater."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/28");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_require_keys("SSL/Supported");
  exit(0);
}

include("audit.inc");
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

if ( get_kb_item("global_settings/disable_ssl_cipher_neg" ) ) exit(1, "Not negotiating the SSL ciphers per user config.");

get_kb_item_or_exit("SSL/Supported");

oakley_grp1_modp = raw_string( # 768 bits
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
  0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
  0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
  0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
  0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
  0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
  0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
  0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
  0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
  0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x3A, 0x36, 0x20,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
);

oakley_grp2_modp = raw_string( # 1024 bits
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
  0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
  0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
  0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
  0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
  0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
  0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
  0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
  0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
  0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
  0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
  0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
  0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
  0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
);

encaps_lookup = make_array(
  ENCAPS_SSLv2,  "SSLv2",
  ENCAPS_SSLv23, "SSLv23",
  ENCAPS_SSLv3,  "SSLv3",
  ENCAPS_TLSv1,  "TLSv1.0",
  COMPAT_ENCAPS_TLSv11, "TLSv1.1",
  COMPAT_ENCAPS_TLSv12, "TLSv1.2"
);

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Get a port to operate on, forking for each one.
port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Find out if the port is open.
if (!get_port_state(port))
  audit(AUDIT_PORT_CLOSED, port);

supported = get_kb_list_or_exit("SSL/Transport/" + port);
cipher_suites = get_kb_list_or_exit("SSL/Ciphers/" + port);

report = '';

foreach encaps (supported)
{
  ssl_ver = NULL;
  v2 = NULL;
  
  if (encaps == ENCAPS_SSLv2)
    ssl_ver = raw_string(0x00, 0x02);
  else if (encaps == ENCAPS_SSLv3 || encaps == ENCAPS_SSLv23)
    ssl_ver = raw_string(0x03, 0x00);
  else if (encaps == ENCAPS_TLSv1)
    ssl_ver = raw_string(0x03, 0x01);
  else if (encaps == COMPAT_ENCAPS_TLSv11)
    ssl_ver = raw_string(0x03, 0x02);
  else if (encaps == COMPAT_ENCAPS_TLSv12)
    ssl_ver = raw_string(0x03, 0x03);

  v2 = (encaps == ENCAPS_SSLv2);

  foreach cipher (cipher_suites)
  {
    # Connect to the port, issuing the StartTLS command if necessary.
    soc = open_sock_ssl(port);
    if (!soc)
      audit(AUDIT_SOCK_FAIL, port, "SSL");

    # Create a ClientHello record
    helo = client_hello(
      version    : ssl_ver,
      cipherspec : ciphers[cipher],
      cspeclen   : mkword(strlen(ciphers[cipher])),
      v2hello    : v2
    );
 
    # Send the ClientHello record.
    send(socket:soc, data:helo);

    skex = NULL;
    hellodone = NULL;

    while (1)
    {
      recs = "";
      repeat
      {
        rec = recv_ssl(socket:soc, timeout:20);
        if (isnull(rec)) break;
        recs += rec;
      } until (!socket_pending(soc));

      if(strlen(recs) == 0) break;

      # Server Key Exchange
      if(!skex)
      {
        skex = ssl_find(
          blob:recs,
          'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
          'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE
        );
      }

      if(skex) break;

      hellodone = ssl_find(
        blob:recs,
        'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
        'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE
      );
      if(hellodone) break;
    }

    close(soc);

    if (!isnull(skex) && strlen(skex['data']) >= 2)
    { 
      skex = ssl_parse_srv_kex(blob:skex['data'], cipher:ciphers_desc[cipher], version: ssl_ver);
      if(skex['kex'] == 'dh')
      {
        mod_bit_len = strlen(skex['dh_p']) * 8;
        dh_mod = skex['dh_p'];

        known_mod = (dh_mod == oakley_grp1_modp || dh_mod == oakley_grp2_modp);

        if((mod_bit_len <= 1024 && mod_bit_len >= 768 && ((report_paranoia == 2) || known_mod)) ||
            mod_bit_len < 768)
        {
          report +=
          '\n  SSL/TLS version  : ' + encaps_lookup[encaps] +
          '\n  Cipher suite     : ' + cipher +
          '\n  Diffie-Hellman MODP size (bits) : ' + mod_bit_len;

          if(dh_mod == oakley_grp1_modp)
             report += 
             '\n    Warning - This is a known static Oakley Group1 modulus. This may make' +
             '\n    the remote host more vulnerable to the Logjam attack.';
          if(dh_mod == oakley_grp2_modp)
             report += 
             '\n    Warning - This is a known static Oakley Group2 modulus. This may make' +
             '\n    the remote host more vulnerable to the Logjam attack.';

          if(mod_bit_len > 768)
            report += '\n  Logjam attack difficulty : Hard (would require nation-state resources)';
          else if(mod_bit_len > 512 && mod_bit_len <= 768)
            report += '\n  Logjam attack difficulty : Medium (would require university resources)';
          else
            report += '\n  Logjam attack difficulty : Easy (could be carried out by individuals)';
          report += '\n';
        }
      }
    }
  }
}

if(report)
{
  report = '\nVulnerable connection combinations :\n' + report;
  if(report_verbosity > 0)
    security_note(port:port, extra:report);
  else security_note(port);
}
else audit(AUDIT_HOST_NOT, "affected");
