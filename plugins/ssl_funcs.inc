#TRUSTED 3c4e57068319ec2756a6c0d2f29cc26aec04d609874098356c0337b43baa7ff38539a58026e5b89677acc68788cb62e78992984823ed41c7d8a67814f93c5cf5f0533a4b13720048685ede7de75e94d67cc0a05708f2b5e71b4f695c5e9aa2fd14d20e84d8492764c21b8c96809405f6be510614541cf9e0ad589679a97d0ed7e4e31917c1d4c41ea72f1e57a3f212f7ec1d4596713cb4e066bb9fb17346f384cd417d908a9e52a47e66a9ab7287e67fd1d1f05dea7b6fb8c8b0b6e658ce377103d6bde3810dfe0c71c5baca2a8012980c984eb7243adeb8757fcac5260e5c89d832d8b5f98249a2bb58b5fbf1bc9313854fa9176b82d5c5c40f588e52cf06803177b47e3a12712de676c47388379763dd0bbcefba39fc223140cec329ba1bfdd171e41ad0e5d780ed09078f66d133fe614e5e9e5feaf6d121e7f547208d21f02502aff95a6260ef921e30a8709e881e4dcd17578f248e33d603e7c71be53ffa7d0bcf88f000da08cf364c468c6692024108a50cfa2fcc8199876fced750327cf913a911725cb6817fad3ff49033600bea683c00a2c123b69ec7d7548fb0b3e85adceb20ba25fe5e37db6e0dcdb3351f5b1ece583bb307b8043205eb76778ffbf19fb47ff1686e4fe9a3e1bc8cbf80c79a9c6cdb4d7351f8859389d7a2ecc68f8d68d0dad4a1860ff505d42d75be6c663f61777aa8a55445f63ecdcaf34f920a
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision 1.98
#
# @include misc_func.inc
# @include byte_func.inc

# Cipher suites.
#
# nb: key names should start with one of "SSL2_", "SSL3_", or "TLS1".
global_var ciphers, ciphers_desc;
# - SSL v2
# -   from OpenSSL's ssl2.h
ciphers["SSL2_CK_NULL_WITH_MD5"]                    = raw_string(0x00, 0x00, 0x00);
ciphers["SSL2_CK_RC4_128_WITH_MD5"]                 = raw_string(0x01, 0x00, 0x80);
ciphers["SSL2_CK_RC4_128_EXPORT40_WITH_MD5"]        = raw_string(0x02, 0x00, 0x80);
ciphers["SSL2_CK_RC2_128_CBC_WITH_MD5"]             = raw_string(0x03, 0x00, 0x80);
ciphers["SSL2_CK_RC2_128_CBC_EXPORT40_WITH_MD5"]    = raw_string(0x04, 0x00, 0x80);
ciphers["SSL2_CK_IDEA_128_CBC_WITH_MD5"]            = raw_string(0x05, 0x00, 0x80);
ciphers["SSL2_CK_DES_64_CBC_WITH_MD5"]              = raw_string(0x06, 0x00, 0x40);
ciphers["SSL2_CK_DES_64_CBC_WITH_SHA"]              = raw_string(0x06, 0x01, 0x40);
ciphers["SSL2_CK_DES_192_EDE3_CBC_WITH_MD5"]        = raw_string(0x07, 0x00, 0xc0);
ciphers["SSL2_CK_DES_192_EDE3_CBC_WITH_SHA"]        = raw_string(0x07, 0x01, 0xc0);
ciphers["SSL2_CK_RC4_64_WITH_MD5"]                  = raw_string(0x08, 0x00, 0x80);
ciphers["SSL2_CK_DES_64_CFB64_WITH_MD5_1"]          = raw_string(0xff, 0x08, 0x00);
ciphers["SSL2_CK_NULL"]                             = raw_string(0xff, 0x08, 0x10);
# - TLS (v1.0 and 1.2)
#
#   nb: TLS 1.0 cipher suites start with 'TLS1_'
#       TLS 1.2 with 'TLS12_'
#
# -   from https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
ciphers["TLS1_CK_NULL_WITH_NULL_NULL"]              = raw_string(0x00, 0x00);
ciphers["TLS1_CK_RSA_WITH_NULL_MD5"]                = raw_string(0x00, 0x01);
ciphers["TLS1_CK_RSA_WITH_NULL_SHA"]                = raw_string(0x00, 0x02);
ciphers["TLS1_CK_RSA_EXPORT_WITH_RC4_40_MD5"]       = raw_string(0x00, 0x03);
ciphers["TLS1_CK_RSA_WITH_RC4_128_MD5"]             = raw_string(0x00, 0x04);
ciphers["TLS1_CK_RSA_WITH_RC4_128_SHA"]             = raw_string(0x00, 0x05);
ciphers["TLS1_CK_RSA_EXPORT_WITH_RC2_CBC_40_MD5"]   = raw_string(0x00, 0x06);
ciphers["TLS1_CK_RSA_WITH_IDEA_CBC_SHA"]            = raw_string(0x00, 0x07);
ciphers["TLS1_CK_RSA_EXPORT_WITH_DES40_CBC_SHA"]    = raw_string(0x00, 0x08);
ciphers["TLS1_CK_RSA_WITH_DES_CBC_SHA"]             = raw_string(0x00, 0x09);
ciphers["TLS1_CK_RSA_WITH_3DES_EDE_CBC_SHA"]        = raw_string(0x00, 0x0A);
ciphers["TLS1_CK_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"] = raw_string(0x00, 0x0B);
ciphers["TLS1_CK_DH_DSS_WITH_DES_CBC_SHA"]          = raw_string(0x00, 0x0C);
ciphers["TLS1_CK_DH_DSS_WITH_3DES_EDE_CBC_SHA"]     = raw_string(0x00, 0x0D);
ciphers["TLS1_CK_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"] = raw_string(0x00, 0x0E);
ciphers["TLS1_CK_DH_RSA_WITH_DES_CBC_SHA"]          = raw_string(0x00, 0x0F);
ciphers["TLS1_CK_DH_RSA_WITH_3DES_EDE_CBC_SHA"]     = raw_string(0x00, 0x10);
ciphers["TLS1_CK_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"]= raw_string(0x00, 0x11);
ciphers["TLS1_CK_DHE_DSS_WITH_DES_CBC_SHA"]         = raw_string(0x00, 0x12);
ciphers["TLS1_CK_DHE_DSS_WITH_3DES_EDE_CBC_SHA"]    = raw_string(0x00, 0x13);
ciphers["TLS1_CK_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"]= raw_string(0x00, 0x14);
ciphers["TLS1_CK_DHE_RSA_WITH_DES_CBC_SHA"]         = raw_string(0x00, 0x15);
ciphers["TLS1_CK_DHE_RSA_WITH_3DES_EDE_CBC_SHA"]    = raw_string(0x00, 0x16);
ciphers["TLS1_CK_DH_anon_EXPORT_WITH_RC4_40_MD5"]   = raw_string(0x00, 0x17);
ciphers["TLS1_CK_DH_anon_WITH_RC4_128_MD5"]         = raw_string(0x00, 0x18);
ciphers["TLS1_CK_DH_anon_EXPORT_WITH_DES40_CBC_SHA"]= raw_string(0x00, 0x19);
ciphers["TLS1_CK_DH_anon_WITH_DES_CBC_SHA"]         = raw_string(0x00, 0x1A);
ciphers["TLS1_CK_DH_anon_WITH_3DES_EDE_CBC_SHA"]    = raw_string(0x00, 0x1B);
ciphers["TLS1_CK_KRB5_WITH_DES_CBC_SHA"]            = raw_string(0x00, 0x1E);
ciphers["TLS1_CK_KRB5_WITH_3DES_EDE_CBC_SHA"]       = raw_string(0x00, 0x1F);
ciphers["TLS1_CK_KRB5_WITH_RC4_128_SHA"]            = raw_string(0x00, 0x20);
ciphers["TLS1_CK_KRB5_WITH_IDEA_CBC_SHA"]           = raw_string(0x00, 0x21);
ciphers["TLS1_CK_KRB5_WITH_DES_CBC_MD5"]            = raw_string(0x00, 0x22);
ciphers["TLS1_CK_KRB5_WITH_3DES_EDE_CBC_MD5"]       = raw_string(0x00, 0x23);
ciphers["TLS1_CK_KRB5_WITH_RC4_128_MD5"]            = raw_string(0x00, 0x24);
ciphers["TLS1_CK_KRB5_WITH_IDEA_CBC_MD5"]           = raw_string(0x00, 0x25);
ciphers["TLS1_CK_KRB5_EXPORT_WITH_DES_CBC_40_SHA"]  = raw_string(0x00, 0x26);
ciphers["TLS1_CK_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"]  = raw_string(0x00, 0x27);
ciphers["TLS1_CK_KRB5_EXPORT_WITH_RC4_40_SHA"]      = raw_string(0x00, 0x28);
ciphers["TLS1_CK_KRB5_EXPORT_WITH_DES_CBC_40_MD5"]  = raw_string(0x00, 0x29);
ciphers["TLS1_CK_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"]  = raw_string(0x00, 0x2A);
ciphers["TLS1_CK_KRB5_EXPORT_WITH_RC4_40_MD5"]      = raw_string(0x00, 0x2B);
ciphers["TLS1_PSK_WITH_NULL_SHA"]                   = raw_string(0x00, 0x2C);
ciphers["TLS1_DHE_PSK_WITH_NULL_SHA"]               = raw_string(0x00, 0x2D);
ciphers["TLS1_RSA_PSK_WITH_NULL_SHA"]               = raw_string(0x00, 0x2E);
ciphers["TLS1_CK_RSA_WITH_AES_128_CBC_SHA"]         = raw_string(0x00, 0x2F);
ciphers["TLS1_CK_DH_DSS_WITH_AES_128_CBC_SHA"]      = raw_string(0x00, 0x30);
ciphers["TLS1_CK_DH_RSA_WITH_AES_128_CBC_SHA"]      = raw_string(0x00, 0x31);
ciphers["TLS1_CK_DHE_DSS_WITH_AES_128_CBC_SHA"]     = raw_string(0x00, 0x32);
ciphers["TLS1_CK_DHE_RSA_WITH_AES_128_CBC_SHA"]     = raw_string(0x00, 0x33);
ciphers["TLS1_CK_DH_anon_WITH_AES_128_CBC_SHA"]     = raw_string(0x00, 0x34);
ciphers["TLS1_CK_RSA_WITH_AES_256_CBC_SHA"]         = raw_string(0x00, 0x35);
ciphers["TLS1_CK_DH_DSS_WITH_AES_256_CBC_SHA"]      = raw_string(0x00, 0x36);
ciphers["TLS1_CK_DH_RSA_WITH_AES_256_CBC_SHA"]      = raw_string(0x00, 0x37);
ciphers["TLS1_CK_DHE_DSS_WITH_AES_256_CBC_SHA"]     = raw_string(0x00, 0x38);
ciphers["TLS1_CK_DHE_RSA_WITH_AES_256_CBC_SHA"]     = raw_string(0x00, 0x39);
ciphers["TLS1_CK_DH_anon_WITH_AES_256_CBC_SHA"]     = raw_string(0x00, 0x3A);
ciphers["TLS1_RSA_WITH_NULL_SHA256"]                = raw_string(0x00, 0x3B);
ciphers["TLS1_RSA_WITH_AES_128_CBC_SHA256"]         = raw_string(0x00, 0x3C);
ciphers["TLS1_RSA_WITH_AES_256_CBC_SHA256"]         = raw_string(0x00, 0x3D);
ciphers["TLS1_DH_DSS_WITH_AES_128_CBC_SHA256"]      = raw_string(0x00, 0x3E);
ciphers["TLS1_DH_RSA_WITH_AES_128_CBC_SHA256"]      = raw_string(0x00, 0x3F);
ciphers["TLS1_DHE_DSS_WITH_AES_128_CBC_SHA256"]     = raw_string(0x00, 0x40);
ciphers["TLS1_DHE_RSA_WITH_AES_128_CBC_SHA256"]     = raw_string(0x00, 0x67);
ciphers["TLS1_DH_DSS_WITH_AES_256_CBC_SHA256"]      = raw_string(0x00, 0x68);
ciphers["TLS1_DH_RSA_WITH_AES_256_CBC_SHA256"]      = raw_string(0x00, 0x69);
ciphers["TLS1_DHE_DSS_WITH_AES_256_CBC_SHA256"]     = raw_string(0x00, 0x6A);
ciphers["TLS1_DHE_RSA_WITH_AES_256_CBC_SHA256"]     = raw_string(0x00, 0x6B);
ciphers["TLS1_DH_anon_WITH_AES_128_CBC_SHA256"]     = raw_string(0x00, 0x6C);
ciphers["TLS1_DH_anon_WITH_AES_256_CBC_SHA256"]     = raw_string(0x00, 0x6D);
# -   nb: these aren't part of the IANA spec but are supported by OpenSSL
#         if TLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES is defined.
ciphers["TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5"]   = raw_string(0x00, 0x60);
ciphers["TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5"]= raw_string(0x00, 0x61);
ciphers["TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA"]  = raw_string(0x00, 0x62);
ciphers["TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"]= raw_string(0x00, 0x63);
ciphers["TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA"]   = raw_string(0x00, 0x64);
ciphers["TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"]= raw_string(0x00, 0x65);
ciphers["TLS1_CK_DHE_DSS_WITH_RC4_128_SHA"]         = raw_string(0x00, 0x66);
# -   nb: Camellia, from RFC 4132
ciphers["TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA"]    = raw_string(0x00, 0x41);
ciphers["TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"] = raw_string(0x00, 0x42);
ciphers["TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"] = raw_string(0x00, 0x43);
ciphers["TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"]= raw_string(0x00, 0x44);
ciphers["TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"]= raw_string(0x00, 0x45);
ciphers["TLS1_CK_DH_anon_WITH_CAMELLIA_128_CBC_SHA"]= raw_string(0x00, 0x46);
ciphers["TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA"]    = raw_string(0x00, 0x84);
ciphers["TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"] = raw_string(0x00, 0x85);
ciphers["TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"] = raw_string(0x00, 0x86);
ciphers["TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"]= raw_string(0x00, 0x87);
ciphers["TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"]= raw_string(0x00, 0x88);
ciphers["TLS1_CK_DH_anon_WITH_CAMELLIA_256_CBC_SHA"]= raw_string(0x00, 0x89);
# -   nb: GOST, draft-chudov-cryptopro-cptls-04.txt
ciphers["TLS1_GOSTR341094_WITH_28147_CNT_IMIT"]     = raw_string(0x00, 0x80);
ciphers["TLS1_GOSTR341001_WITH_28147_CNT_IMIT"]     = raw_string(0x00, 0x81);
ciphers["TLS1_GOSTR341094_WITH_NULL_GOSTR3411"]     = raw_string(0x00, 0x82);
ciphers["TLS1_GOSTR341001_WITH_NULL_GOSTR3411"]     = raw_string(0x00, 0x83);
# -   nb: TLS w/ pre-shared keys, RFC 4279.
ciphers["TLS1_CK_PSK_WITH_RC4_128_SHA"]             = raw_string(0x00, 0x8A);
ciphers["TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA"]        = raw_string(0x00, 0x8B);
ciphers["TLS1_CK_PSK_WITH_AES_128_CBC_SHA"]         = raw_string(0x00, 0x8C);
ciphers["TLS1_CK_PSK_WITH_AES_256_CBC_SHA"]         = raw_string(0x00, 0x8D);
ciphers["TLS1_CK_DHE_PSK_WITH_RC4_128_SHA"]         = raw_string(0x00, 0x8E);
ciphers["TLS1_CK_DHE_PSK_WITH_3DES_EDE_CBC_SHA"]    = raw_string(0x00, 0x8F);
ciphers["TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA"]     = raw_string(0x00, 0x90);
ciphers["TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA"]     = raw_string(0x00, 0x91);
ciphers["TLS1_CK_RSA_PSK_WITH_RC4_128_SHA"]         = raw_string(0x00, 0x92);
ciphers["TLS1_CK_RSA_PSK_WITH_3DES_EDE_CBC_SHA"]    = raw_string(0x00, 0x93);
ciphers["TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA"]     = raw_string(0x00, 0x94);
ciphers["TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA"]     = raw_string(0x00, 0x95);
# -   nb: SEED Cipher Suites, RFC 4162
ciphers["TLS1_CK_RSA_WITH_SEED_CBC_SHA"]            = raw_string(0x00, 0x96);
ciphers["TLS1_CK_DH_DSS_WITH_SEED_CBC_SHA"]         = raw_string(0x00, 0x97);
ciphers["TLS1_CK_DH_RSA_WITH_SEED_CBC_SHA"]         = raw_string(0x00, 0x98);
ciphers["TLS1_CK_DHE_DSS_WITH_SEED_CBC_SHA"]        = raw_string(0x00, 0x99);
ciphers["TLS1_CK_DHE_RSA_WITH_SEED_CBC_SHA"]        = raw_string(0x00, 0x9A);
ciphers["TLS1_CK_DH_anon_WITH_SEED_CBC_SHA"]        = raw_string(0x00, 0x9B);
# -   nb: AES Galois Counter Mode (GCM), RFC 5288
ciphers["TLS12_RSA_WITH_AES_128_GCM_SHA256"]        = raw_string(0x00, 0x9C);
ciphers["TLS12_RSA_WITH_AES_256_GCM_SHA384"]        = raw_string(0x00, 0x9D);
ciphers["TLS12_DHE_RSA_WITH_AES_128_GCM_SHA256"]    = raw_string(0x00, 0x9E);
ciphers["TLS12_DHE_RSA_WITH_AES_256_GCM_SHA384"]    = raw_string(0x00, 0x9F);
ciphers["TLS12_DH_RSA_WITH_AES_128_GCM_SHA256"]     = raw_string(0x00, 0xA0);
ciphers["TLS12_DH_RSA_WITH_AES_256_GCM_SHA384"]     = raw_string(0x00, 0xA1);
ciphers["TLS12_DHE_DSS_WITH_AES_128_GCM_SHA256"]    = raw_string(0x00, 0xA2);
ciphers["TLS12_DHE_DSS_WITH_AES_256_GCM_SHA384"]    = raw_string(0x00, 0xA3);
ciphers["TLS12_DH_DSS_WITH_AES_128_GCM_SHA256"]     = raw_string(0x00, 0xA4);
ciphers["TLS12_DH_DSS_WITH_AES_256_GCM_SHA384"]     = raw_string(0x00, 0xA5);
ciphers["TLS12_DH_anon_WITH_AES_128_GCM_SHA256"]    = raw_string(0x00, 0xA6);
ciphers["TLS12_DH_anon_WITH_AES_256_GCM_SHA384"]    = raw_string(0x00, 0xA7);
# -   nb: Pre-Shared Key w/ SHA-256/384 and AES Galois Counter Mode, RFC 5487
ciphers["TLS12_PSK_WITH_AES_128_GCM_SHA256"]        = raw_string(0x00, 0xA8);
ciphers["TLS12_PSK_WITH_AES_256_GCM_SHA384"]        = raw_string(0x00, 0xA9);
ciphers["TLS12_DHE_PSK_WITH_AES_128_GCM_SHA256"]    = raw_string(0x00, 0xAA);
ciphers["TLS12_DHE_PSK_WITH_AES_256_GCM_SHA384"]    = raw_string(0x00, 0xAB);
ciphers["TLS12_RSA_PSK_WITH_AES_128_GCM_SHA256"]    = raw_string(0x00, 0xAC);
ciphers["TLS12_RSA_PSK_WITH_AES_256_GCM_SHA384"]    = raw_string(0x00, 0xAD);
ciphers["TLS1_PSK_WITH_AES_128_CBC_SHA256"]         = raw_string(0x00, 0xAE);
ciphers["TLS1_PSK_WITH_AES_256_CBC_SHA384"]         = raw_string(0x00, 0xAF);
ciphers["TLS1_PSK_WITH_NULL_SHA256"]                = raw_string(0x00, 0xB0);
ciphers["TLS1_PSK_WITH_NULL_SHA384"]                = raw_string(0x00, 0xB1);
ciphers["TLS1_DHE_PSK_WITH_AES_128_CBC_SHA256"]     = raw_string(0x00, 0xB2);
ciphers["TLS1_DHE_PSK_WITH_AES_256_CBC_SHA384"]     = raw_string(0x00, 0xB3);
ciphers["TLS1_DHE_PSK_WITH_NULL_SHA256"]            = raw_string(0x00, 0xB4);
ciphers["TLS1_DHE_PSK_WITH_NULL_SHA384"]            = raw_string(0x00, 0xB5);
ciphers["TLS1_RSA_PSK_WITH_AES_128_CBC_SHA256"]     = raw_string(0x00, 0xB6);
ciphers["TLS1_RSA_PSK_WITH_AES_256_CBC_SHA384"]     = raw_string(0x00, 0xB7);
ciphers["TLS1_RSA_PSK_WITH_NULL_SHA256"]            = raw_string(0x00, 0xB8);
ciphers["TLS1_RSA_PSK_WITH_NULL_SHA384"]            = raw_string(0x00, 0xB9);
# -   nb: Camellia, from RFC-kato-tls-rfc4132bis-05.txt
ciphers["TLS1_RSA_WITH_CAMELLIA_128_CBC_SHA256"]    = raw_string(0x00, 0xBA);
ciphers["TLS1_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"] = raw_string(0x00, 0xBB);
ciphers["TLS1_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"] = raw_string(0x00, 0xBC);
ciphers["TLS1_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"]= raw_string(0x00, 0xBD);
ciphers["TLS1_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"]= raw_string(0x00, 0xBE);
ciphers["TLS1_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"]= raw_string(0x00, 0xBF);
ciphers["TLS1_RSA_WITH_CAMELLIA_256_CBC_SHA256"]    = raw_string(0x00, 0xC0);
ciphers["TLS1_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"] = raw_string(0x00, 0xC1);
ciphers["TLS1_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"] = raw_string(0x00, 0xC2);
ciphers["TLS1_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"]= raw_string(0x00, 0xC3);
ciphers["TLS1_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"]= raw_string(0x00, 0xC4);
ciphers["TLS1_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"]= raw_string(0x00, 0xC5);
# -   nb: Elliptic Curve Cryptography (ECC), RFC 4492
ciphers["TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA"]         = raw_string(0xC0, 0x01);
ciphers["TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA"]      = raw_string(0xC0, 0x02);
ciphers["TLS1_CK_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"] = raw_string(0xC0, 0x03);
ciphers["TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA"]  = raw_string(0xC0, 0x04);
ciphers["TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA"]  = raw_string(0xC0, 0x05);
ciphers["TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA"]        = raw_string(0xC0, 0x06);
ciphers["TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA"]     = raw_string(0xC0, 0x07);
ciphers["TLS1_CK_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"]= raw_string(0xC0, 0x08);
ciphers["TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"] = raw_string(0xC0, 0x09);
ciphers["TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"] = raw_string(0xC0, 0x0A);
ciphers["TLS1_CK_ECDH_RSA_WITH_NULL_SHA"]           = raw_string(0xC0, 0x0B);
ciphers["TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA"]        = raw_string(0xC0, 0x0C);
ciphers["TLS1_CK_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"]   = raw_string(0xC0, 0x0D);
ciphers["TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA"]    = raw_string(0xC0, 0x0E);
ciphers["TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA"]    = raw_string(0xC0, 0x0F);
ciphers["TLS1_CK_ECDHE_RSA_WITH_NULL_SHA"]          = raw_string(0xC0, 0x10);
ciphers["TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA"]       = raw_string(0xC0, 0x11);
ciphers["TLS1_CK_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"]  = raw_string(0xC0, 0x12);
ciphers["TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA"]   = raw_string(0xC0, 0x13);
ciphers["TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA"]   = raw_string(0xC0, 0x14);
ciphers["TLS1_CK_ECDH_anon_NULL_WITH_SHA"]          = raw_string(0xC0, 0x15);
ciphers["TLS1_CK_ECDH_anon_WITH_RC4_128_SHA"]       = raw_string(0xC0, 0x16);
ciphers["TLS1_CK_ECDH_anon_WITH_3DES_EDE_CBC_SHA"]  = raw_string(0xC0, 0x17);
ciphers["TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA"]   = raw_string(0xC0, 0x18);
ciphers["TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA"]   = raw_string(0xC0, 0x19);
# -   nb: Secure Remote Password (SRP), RFC 5054
ciphers["TLS1_SRP_SHA_WITH_3DES_EDE_CBC_SHA"]       = raw_string(0xC0, 0x1A);
ciphers["TLS1_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"]   = raw_string(0xC0, 0x1B);
ciphers["TLS1_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"]   = raw_string(0xC0, 0x1C);
ciphers["TLS1_SRP_SHA_WITH_AES_128_CBC_SHA"]        = raw_string(0xC0, 0x1D);
ciphers["TLS1_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"]    = raw_string(0xC0, 0x1E);
ciphers["TLS1_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"]    = raw_string(0xC0, 0x1F);
ciphers["TLS1_SRP_SHA_WITH_AES_256_CBC_SHA"]        = raw_string(0xC0, 0x20);
ciphers["TLS1_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"]    = raw_string(0xC0, 0x21);
ciphers["TLS1_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"]    = raw_string(0xC0, 0x22);
# -   nb: Elliptic Curve Cipher Suites w/ SHA-256/384 and AES Galois Counter Mode (GCM), RFC 5289
ciphers["TLS1_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"] = raw_string(0xC0, 0x23);
ciphers["TLS1_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"] = raw_string(0xC0, 0x24);
ciphers["TLS1_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"]  = raw_string(0xC0, 0x25);
ciphers["TLS1_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"]  = raw_string(0xC0, 0x26);
ciphers["TLS1_ECDHE_RSA_WITH_AES_128_CBC_SHA256"]   = raw_string(0xC0, 0x27);
ciphers["TLS1_ECDHE_RSA_WITH_AES_256_CBC_SHA384"]   = raw_string(0xC0, 0x28);
ciphers["TLS1_ECDH_RSA_WITH_AES_128_CBC_SHA256"]    = raw_string(0xC0, 0x29);
ciphers["TLS1_ECDH_RSA_WITH_AES_256_CBC_SHA384"]    = raw_string(0xC0, 0x2A);
ciphers["TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"]= raw_string(0xC0, 0x2B);
ciphers["TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"]= raw_string(0xC0, 0x2C);
ciphers["TLS12_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"] = raw_string(0xC0, 0x2D);
ciphers["TLS12_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"] = raw_string(0xC0, 0x2E);
ciphers["TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]  = raw_string(0xC0, 0x2F);
ciphers["TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]  = raw_string(0xC0, 0x30);
ciphers["TLS12_ECDH_RSA_WITH_AES_128_GCM_SHA256"]   = raw_string(0xC0, 0x31);
ciphers["TLS12_ECDH_RSA_WITH_AES_256_GCM_SHA384"]   = raw_string(0xC0, 0x32);
# -   nb: ECDHE_PSK, RFC 5489
ciphers["TLS1_ECDHE_PSK_WITH_RC4_128_SHA"]          = raw_string(0xC0, 0x33);
ciphers["TLS1_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"]     = raw_string(0xC0, 0x34);
ciphers["TLS1_ECDHE_PSK_WITH_AES_128_CBC_SHA"]      = raw_string(0xC0, 0x35);
ciphers["TLS1_ECDHE_PSK_WITH_AES_256_CBC_SHA"]      = raw_string(0xC0, 0x36);
ciphers["TLS1_ECDHE_PSK_WITH_AES_128_CBC_SHA256"]   = raw_string(0xC0, 0x37);
ciphers["TLS1_ECDHE_PSK_WITH_AES_256_CBC_SHA384"]   = raw_string(0xC0, 0x38);
ciphers["TLS1_ECDHE_PSK_WITH_NULL_SHA"]             = raw_string(0xC0, 0x39);
ciphers["TLS1_ECDHE_PSK_WITH_NULL_SHA256"]          = raw_string(0xC0, 0x3A);
ciphers["TLS1_ECDHE_PSK_WITH_NULL_SHA384"]          = raw_string(0xC0, 0x3B);
# -   nb: Ciphers per RFC 6367
ciphers["TLS12_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"]  = raw_string(0xC0, 0x72);
ciphers["TLS12_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"]  = raw_string(0xC0, 0x73);
ciphers["TLS12_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"]   = raw_string(0xC0, 0x74);
ciphers["TLS12_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"]   = raw_string(0xC0, 0x75);
ciphers["TLS12_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"]    = raw_string(0xC0, 0x76);
ciphers["TLS12_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"]    = raw_string(0xC0, 0x77);
ciphers["TLS12_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"]     = raw_string(0xC0, 0x78);
ciphers["TLS12_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"]     = raw_string(0xC0, 0x79);
ciphers["TLS12_RSA_WITH_CAMELLIA_128_GCM_SHA256"]          = raw_string(0xC0, 0x7A);
ciphers["TLS12_RSA_WITH_CAMELLIA_256_GCM_SHA384"]          = raw_string(0xC0, 0x7B);
ciphers["TLS12_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"]      = raw_string(0xC0, 0x7C);
ciphers["TLS12_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"]      = raw_string(0xC0, 0x7D);
ciphers["TLS12_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256"]       = raw_string(0xC0, 0x7E);
ciphers["TLS12_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384"]       = raw_string(0xC0, 0x7F);
ciphers["TLS12_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"]      = raw_string(0xC0, 0x80);
ciphers["TLS12_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384"]      = raw_string(0xC0, 0x81);
ciphers["TLS12_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256"]       = raw_string(0xC0, 0x82);
ciphers["TLS12_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384"]       = raw_string(0xC0, 0x83);
ciphers["TLS12_DH_anon_WITH_CAMELLIA_128_GCM_SHA256"]      = raw_string(0xC0, 0x84);
ciphers["TLS12_DH_anon_WITH_CAMELLIA_256_GCM_SHA384"]      = raw_string(0xC0, 0x85);
ciphers["TLS12_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"]  = raw_string(0xC0, 0x86);
ciphers["TLS12_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"]  = raw_string(0xC0, 0x87);
ciphers["TLS12_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"]   = raw_string(0xC0, 0x88);
ciphers["TLS12_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"]   = raw_string(0xC0, 0x89);
ciphers["TLS12_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"]    = raw_string(0xC0, 0x8A);
ciphers["TLS12_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"]    = raw_string(0xC0, 0x8B);
ciphers["TLS12_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256"]     = raw_string(0xC0, 0x8C);
ciphers["TLS12_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384"]     = raw_string(0xC0, 0x8D);
ciphers["TLS12_PSK_WITH_CAMELLIA_128_GCM_SHA256"]          = raw_string(0xC0, 0x8E);
ciphers["TLS12_PSK_WITH_CAMELLIA_256_GCM_SHA384"]          = raw_string(0xC0, 0x8F);
ciphers["TLS12_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256"]      = raw_string(0xC0, 0x90);
ciphers["TLS12_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384"]      = raw_string(0xC0, 0x91);
ciphers["TLS12_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256"]      = raw_string(0xC0, 0x92);
ciphers["TLS12_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384"]      = raw_string(0xC0, 0x93);
ciphers["TLS12_PSK_WITH_CAMELLIA_128_CBC_SHA256"]          = raw_string(0xC0, 0x94);
ciphers["TLS12_PSK_WITH_CAMELLIA_256_CBC_SHA384"]          = raw_string(0xC0, 0x95);
ciphers["TLS12_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"]      = raw_string(0xC0, 0x96);
ciphers["TLS12_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"]      = raw_string(0xC0, 0x97);
ciphers["TLS12_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"]      = raw_string(0xC0, 0x98);
ciphers["TLS12_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"]      = raw_string(0xC0, 0x99);
ciphers["TLS12_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"]    = raw_string(0xC0, 0x9A);
ciphers["TLS12_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"]    = raw_string(0xC0, 0x9B);

# -   nb: Ciphers per RFC 6655
ciphers["TLS12_RSA_WITH_AES_128_CCM"]                      = raw_string(0xC0, 0x9C);
ciphers["TLS12_RSA_WITH_AES_256_CCM"]                      = raw_string(0xC0, 0x9D);
ciphers["TLS12_DHE_RSA_WITH_AES_128_CCM"]                  = raw_string(0xC0, 0x9E);
ciphers["TLS12_DHE_RSA_WITH_AES_256_CCM"]                  = raw_string(0xC0, 0x9F);
ciphers["TLS12_RSA_WITH_AES_128_CCM_8"]                    = raw_string(0xC0, 0xA0);
ciphers["TLS12_RSA_WITH_AES_256_CCM_8"]                    = raw_string(0xC0, 0xA1);
ciphers["TLS12_DHE_RSA_WITH_AES_128_CCM_8"]                = raw_string(0xC0, 0xA2);
ciphers["TLS12_DHE_RSA_WITH_AES_256_CCM_8"]                = raw_string(0xC0, 0xA3);
ciphers["TLS12_PSK_WITH_AES_128_CCM"]                      = raw_string(0xC0, 0xA4);
ciphers["TLS12_PSK_WITH_AES_256_CCM"]                      = raw_string(0xC0, 0xA5);
ciphers["TLS12_DHE_PSK_WITH_AES_128_CCM"]                  = raw_string(0xC0, 0xA6);
ciphers["TLS12_DHE_PSK_WITH_AES_256_CCM"]                  = raw_string(0xC0, 0xA7);
ciphers["TLS12_PSK_WITH_AES_128_CCM_8"]                    = raw_string(0xC0, 0xA8);
ciphers["TLS12_PSK_WITH_AES_256_CCM_8"]                    = raw_string(0xC0, 0xA9);
ciphers["TLS12_PSK_DHE_WITH_AES_128_CCM_8"]                = raw_string(0xC0, 0xAA);
ciphers["TLS12_PSK_DHE_WITH_AES_256_CCM_8"]                = raw_string(0xC0, 0xAB);

# -   nb: Ciphers per RFC 7251
ciphers["TLS12_ECDHE_ECDSA_WITH_AES_128_CCM"]              = raw_string(0xC0, 0xAC);
ciphers["TLS12_ECDHE_ECDSA_WITH_AES_256_CCM"]              = raw_string(0xC0, 0xAD);
ciphers["TLS12_ECDHE_ECDSA_WITH_AES_128_CCM_8"]            = raw_string(0xC0, 0xAE);
ciphers["TLS12_ECDHE_ECDSA_WITH_AES_256_CCM_8"]            = raw_string(0xC0, 0xAF);

# -   nb: Ciphers per RFC 7905
ciphers["TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"]     = raw_string(0xCC, 0xA8);
ciphers["TLS12_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"]   = raw_string(0xCC, 0xA9);
ciphers["TLS12_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"]       = raw_string(0xCC, 0xAA);

ciphers["TLS12_PSK_WITH_CHACHA20_POLY1305_SHA256"]           = raw_string(0xCC, 0xAB);
ciphers["TLS12_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"]     = raw_string(0xCC, 0xAC);
ciphers["TLS12_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"]       = raw_string(0xCC, 0xAD);
ciphers["TLS12_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"]       = raw_string(0xCC, 0xAE);

# Other ciphers not in IANA registry
ciphers["SSL3_FORTEZZA_KEA_WITH_NULL_SHA"]                = raw_string(0x00, 0x1C);
ciphers["SSL3_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA"]        = raw_string(0x00, 0x1D);

# http://www-archive.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
ciphers["SSL3_RSA_FIPS_WITH_DES_CBC_SHA"]                 = raw_string(0xFE, 0xFE);
ciphers["SSL3_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"]            = raw_string(0xFE, 0xFF);
ciphers["SSL3_RSA_FIPS_WITH_DES_CBC_SHA_PRIVATE"]         = raw_string(0xFF, 0xE1);
ciphers["SSL3_RSA_FIPS_WITH_3DES_EDE_CBC_SHA_PRIVATE"]    = raw_string(0xFF, 0xE0);


# Cipher descriptions; fields are
#   <OpenSSL ciphername>
#   <protocol version>
#   Kx=<key exchange>
#   Au=<authentication>
#   Enc=<symmetric encryption method>
#   Mac=<message authentication code>
#   <export flag>
ciphers_desc["SSL2_CK_NULL_WITH_MD5"]                    = "NULL-MD5|SSLv2|Kx=RSA|Au=RSA|Enc=None|Mac=MD5";
ciphers_desc["SSL2_CK_RC4_128_WITH_MD5"]                 = "RC4-MD5|SSLv2|Kx=RSA|Au=RSA|Enc=RC4(128)|Mac=MD5";
ciphers_desc["SSL2_CK_RC4_128_EXPORT40_WITH_MD5"]        = "EXP-RC4-MD5|SSLv2|Kx=RSA(512)|Au=RSA|Enc=RC4(40)|Mac=MD5|export";
ciphers_desc["SSL2_CK_RC2_128_CBC_WITH_MD5"]             = "RC2-CBC-MD5|SSLv2|Kx=RSA|Au=RSA|Enc=RC2-CBC(128)|Mac=MD5";
ciphers_desc["SSL2_CK_RC2_128_CBC_EXPORT40_WITH_MD5"]    = "EXP-RC2-CBC-MD5|SSLv2|Kx=RSA(512)|Au=RSA|Enc=RC2-CBC(40)|Mac=MD5|export";
ciphers_desc["SSL2_CK_IDEA_128_CBC_WITH_MD5"]            = "IDEA-CBC-MD5|SSLv2|Kx=RSA|Au=RSA|Enc=IDEA-CBC(128)|Mac=MD5";
ciphers_desc["SSL2_CK_DES_64_CBC_WITH_MD5"]              = "DES-CBC-MD5|SSLv2|Kx=RSA|Au=RSA|Enc=DES-CBC(56)|Mac=MD5";
ciphers_desc["SSL2_CK_DES_64_CBC_WITH_SHA"]              = "DES-CBC-SHA|SSLv2|Kx=RSA|Au=RSA|Enc=DES-CBC(56)|Mac=SHA1";
ciphers_desc["SSL2_CK_DES_192_EDE3_CBC_WITH_MD5"]        = "DES-CBC3-MD5|SSLv2|Kx=RSA|Au=RSA|Enc=3DES-CBC(168)|Mac=MD5";
ciphers_desc["SSL2_CK_DES_192_EDE3_CBC_WITH_SHA"]        = "DES-CBC3-SHA|SSLv2|Kx=RSA|Au=RSA|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["SSL2_CK_RC4_64_WITH_MD5"]                  = "RC4-64-MD5|SSLv2|Kx=RSA|Au=RSA|Enc=RC4(64)|Mac=MD5";
ciphers_desc["SSL2_CK_DES_64_CFB64_WITH_MD5_1"]          = "DES-CFB-M1|SSLv2|Kx=RSA|Au=RSA|Enc=DES(56)|Mac=MD5 with 1 byte";
ciphers_desc["SSL2_CK_NULL"]                             = "NULL|SSLv2|Kx=RSA|Au=RSA|Enc=None|Mac=None";
ciphers_desc["TLS1_CK_NULL_WITH_NULL_NULL"]              = "TLS-NULL-NULL-NULL|TLSv1|Kx=None|Au=None|Enc=None|Mac=None";
ciphers_desc["TLS1_CK_RSA_WITH_NULL_MD5"]                = "NULL-MD5|TLSv1|Kx=RSA|Au=RSA|Enc=None|Mac=MD5";
ciphers_desc["TLS1_CK_RSA_WITH_NULL_SHA"]                = "NULL-SHA|TLSv1|Kx=RSA|Au=RSA|Enc=None|Mac=SHA1";
ciphers_desc["TLS1_CK_RSA_EXPORT_WITH_RC4_40_MD5"]       = "EXP-RC4-MD5|TLSv1|Kx=RSA(512)|Au=RSA|Enc=RC4(40)|Mac=MD5|export";
ciphers_desc["TLS1_CK_RSA_WITH_RC4_128_MD5"]             = "RC4-MD5|TLSv1|Kx=RSA|Au=RSA|Enc=RC4(128)|Mac=MD5";
ciphers_desc["TLS1_CK_RSA_WITH_RC4_128_SHA"]             = "RC4-SHA|TLSv1|Kx=RSA|Au=RSA|Enc=RC4(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_RSA_EXPORT_WITH_RC2_CBC_40_MD5"]   = "EXP-RC2-CBC-MD5|TLSv1|Kx=RSA(512)|Au=RSA|Enc=RC2-CBC(40)|Mac=MD5|export";
ciphers_desc["TLS1_CK_RSA_WITH_IDEA_CBC_SHA"]            = "IDEA-CBC-SHA|TLSv1|Kx=RSA|Au=RSA|Enc=IDEA-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_RSA_EXPORT_WITH_DES40_CBC_SHA"]    = "EXP-DES-CBC-SHA|TLSv1|Kx=RSA(512)|Au=RSA|Enc=DES-CBC(40)|Mac=SHA1|export";
ciphers_desc["TLS1_CK_RSA_WITH_DES_CBC_SHA"]             = "DES-CBC-SHA|TLSv1|Kx=RSA|Au=RSA|Enc=DES-CBC(56)|Mac=SHA1";
ciphers_desc["TLS1_CK_RSA_WITH_3DES_EDE_CBC_SHA"]        = "DES-CBC3-SHA|TLSv1|Kx=RSA|Au=RSA|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"] = "EXP-DH-DSS-DES-CBC-SHA|TLSv1|Kx=StaticDH(512)|Au=DSS|Enc=DES-CBC(40)|Mac=SHA1|export";
ciphers_desc["TLS1_CK_DH_DSS_WITH_DES_CBC_SHA"]          = "DH-DSS-DES-CBC-SHA|TLSv1|Kx=StaticDH|Au=DSS|Enc=DES-CBC(56)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_DSS_WITH_3DES_EDE_CBC_SHA"]     = "DH-DSS-DES-CBC3-SHA|TLSv1|Kx=StaticDH|Au=DSS|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"] = "EXP-DH-RSA-DES-CBC-SHA|TLSv1|Kx=StaticDH(512)|Au=RSA|Enc=DES-CBC(40)|Mac=SHA1|export";
ciphers_desc["TLS1_CK_DH_RSA_WITH_DES_CBC_SHA"]          = "DH-RSA-DES-CBC-SHA|TLSv1|Kx=StaticDH|Au=RSA|Enc=DES-CBC(56)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_RSA_WITH_3DES_EDE_CBC_SHA"]     = "DH-RSA-DES-CBC3-SHA|TLSv1|Kx=StaticDH|Au=RSA|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["TLS1_CK_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"]= "EXP-EDH-DSS-DES-CBC-SHA|TLSv1|Kx=DH(512)|Au=DSS|Enc=DES-CBC(40)|Mac=SHA1|export";
ciphers_desc["TLS1_CK_DHE_DSS_WITH_DES_CBC_SHA"]         = "EDH-DSS-DES-CBC-SHA|TLSv1|Kx=DH|Au=DSS|Enc=DES-CBC(56)|Mac=SHA1";
ciphers_desc["TLS1_CK_DHE_DSS_WITH_3DES_EDE_CBC_SHA"]    = "EDH-DSS-DES-CBC3-SHA|TLSv1|Kx=DH|Au=DSS|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["TLS1_CK_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"]= "EXP-EDH-RSA-DES-CBC-SHA|TLSv1|Kx=DH(512)|Au=RSA|Enc=DES-CBC(40)|Mac=SHA1|export";
ciphers_desc["TLS1_CK_DHE_RSA_WITH_DES_CBC_SHA"]         = "EDH-RSA-DES-CBC-SHA|TLSv1|Kx=DH|Au=RSA|Enc=DES-CBC(56)|Mac=SHA1";
ciphers_desc["TLS1_CK_DHE_RSA_WITH_3DES_EDE_CBC_SHA"]    = "EDH-RSA-DES-CBC3-SHA|TLSv1|Kx=DH|Au=RSA|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_anon_EXPORT_WITH_RC4_40_MD5"]   = "EXP-ADH-RC4-MD5|TLSv1|Kx=DH(512)|Au=None|Enc=RC4(40)|Mac=MD5|export";
ciphers_desc["TLS1_CK_DH_anon_WITH_RC4_128_MD5"]         = "ADH-RC4-MD5|TLSv1|Kx=DH|Au=None|Enc=RC4(128)|Mac=MD5";
ciphers_desc["TLS1_CK_DH_anon_EXPORT_WITH_DES40_CBC_SHA"]= "EXP-ADH-DES-CBC-SHA|TLSv1|Kx=DH(512)|Au=None|Enc=DES-CBC(40)|Mac=SHA1|export";
ciphers_desc["TLS1_CK_DH_anon_WITH_DES_CBC_SHA"]         = "ADH-DES-CBC-SHA|TLSv1|Kx=DH|Au=None|Enc=DES-CBC(56)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_anon_WITH_3DES_EDE_CBC_SHA"]    = "ADH-DES-CBC3-SHA|TLSv1|Kx=DH|Au=None|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["TLS1_CK_KRB5_WITH_DES_CBC_SHA"]            = "KRB5-DES-CBC-SHA|TLSv1|Kx=KRB5|Au=KRB5|Enc=DES-CBC(56)|MAC=SHA1";
ciphers_desc["TLS1_CK_KRB5_WITH_3DES_EDE_CBC_SHA"]       = "KRB5-DES-CBC3-SHA|TLSv1|Kx=KRB5|Au=KRB5|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["TLS1_CK_KRB5_WITH_RC4_128_SHA"]            = "KRB5-RC4-SHA|TLSv1|Kx=KRB5|Au=KRB5|Enc=RC4(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_KRB5_WITH_IDEA_CBC_SHA"]           = "KRB5-IDEA-CBC-SHA|TLSv1|Kx=KRB5|Au=KRB5|Enc=IDEA-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_KRB5_WITH_DES_CBC_MD5"]            = "KRB5-DES-CBC-MD5|TLSv1|Kx=KRB5|Au=KRB5|Enc=DES-CBC(56)|Mac=MD5";
ciphers_desc["TLS1_CK_KRB5_WITH_3DES_EDE_CBC_MD5"]       = "KRB5-DES-CBC3-MD5|TLSv1|Kx=KRB5|Au=KRB5|Enc=3DES-CBC(168)|Mac=MD5";
ciphers_desc["TLS1_CK_KRB5_WITH_RC4_128_MD5"]            = "KRB5-RC4-MD5|TLSv1|Kx=KRB5|Au=KRB5|Enc=RC4(128)|Mac=MD5";
ciphers_desc["TLS1_CK_KRB5_WITH_IDEA_CBC_MD5"]           = "KRB5-IDEA-CBC-MD5|TLSv1|Kx=KRB5|Au=KRB5|Enc=IDEA-CBC(128)|Mac=MD5";
ciphers_desc["TLS1_CK_KRB5_EXPORT_WITH_DES_CBC_40_SHA"]  = "EXP-KRB5-DES-CBC-SHA|TLSv1|Kx=KRB5|Au=KRB5|Enc=DES-CBC(40)|Mac=SHA1|export";
ciphers_desc["TLS1_CK_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"]  = "EXP-KRB5-RC2-CBC-SHA|TLSv1|Kx=KRB5|Au=KRB5|Enc=RC2-CBC(40)|Mac=SHA1|export";
ciphers_desc["TLS1_CK_KRB5_EXPORT_WITH_RC4_40_SHA"]      = "EXP-KRB5-RC4-SHA|TLSv1|Kx=KRB5|Au=KRB5|Enc=RC4(40)|Mac=SHA1|export";
ciphers_desc["TLS1_CK_KRB5_EXPORT_WITH_DES_CBC_40_MD5"]  = "EXP-KRB5-DES-CBC-MD5|TLSv1|Kx=KRB5|Au=KRB5|Enc=DES-CBC(40)|Mac=MD5|export";
ciphers_desc["TLS1_CK_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"]  = "EXP-KRB5-RC2-CBC-MD5|TLSv1|Kx=KRB5|Au=KRB5|Enc=RC2-CBC(40)|Mac=MD5|export";
ciphers_desc["TLS1_CK_KRB5_EXPORT_WITH_RC4_40_MD5"]      = "EXP-KRB5-RC4-MD5|TLSv1|Kx=KRB5|Au=KRB5|Enc=RC4(40)|Mac=MD5|export";
ciphers_desc["TLS1_PSK_WITH_NULL_SHA"]                   = "PSK-NULL-SHA|TLSv1|Kx=PSK|Au=PSK|Enc=NULL|Mac=SHA1";
ciphers_desc["TLS1_DHE_PSK_WITH_NULL_SHA"]               = "DHE-PSK-NULL-SHA|TLSv1|Kx=DH|Au=PSK|Enc=NULL|Mac=SHA1";
ciphers_desc["TLS1_RSA_PSK_WITH_NULL_SHA"]               = "RSA-PSK-NULL-SHA|TLSv1|Kx=RSA|Au=PSK|Enc=NULL|Mac=SHA1";
ciphers_desc["TLS1_CK_RSA_WITH_AES_128_CBC_SHA"]         = "AES128-SHA|TLSv1|Kx=RSA|Au=RSA|Enc=AES-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_DSS_WITH_AES_128_CBC_SHA"]      = "DH-DSS-AES128-SHA|TLSv1|Kx=StaticDH|Au=DSS|Enc=AES-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_RSA_WITH_AES_128_CBC_SHA"]      = "DH-RSA-AES128-SHA|TLSv1|Kx=StaticDH|Au=RSA|Enc=AES-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_DHE_DSS_WITH_AES_128_CBC_SHA"]     = "DHE-DSS-AES128-SHA|TLSv1|Kx=DH|Au=DSS|Enc=AES-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_DHE_RSA_WITH_AES_128_CBC_SHA"]     = "DHE-RSA-AES128-SHA|TLSv1|Kx=DH|Au=RSA|Enc=AES-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_anon_WITH_AES_128_CBC_SHA"]     = "ADH-AES128-SHA|TLSv1|Kx=DH|Au=None|Enc=AES-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_RSA_WITH_AES_256_CBC_SHA"]         = "AES256-SHA|TLSv1|Kx=RSA|Au=RSA|Enc=AES-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_DSS_WITH_AES_256_CBC_SHA"]      = "DH-DSS-AES256-SHA|TLSv1|Kx=StaticDH|Au=DSS|Enc=AES-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_RSA_WITH_AES_256_CBC_SHA"]      = "DH-RSA-AES256-SHA|TLSv1|Kx=StaticDH|Au=RSA|Enc=AES-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_CK_DHE_DSS_WITH_AES_256_CBC_SHA"]     = "DHE-DSS-AES256-SHA|TLSv1|Kx=DH|Au=DSS|Enc=AES-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_CK_DHE_RSA_WITH_AES_256_CBC_SHA"]     = "DHE-RSA-AES256-SHA|TLSv1|Kx=DH|Au=RSA|Enc=AES-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_anon_WITH_AES_256_CBC_SHA"]     = "ADH-AES256-SHA|TLSv1|Kx=DH|Au=None|Enc=AES-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_RSA_WITH_NULL_SHA256"]                = "RSA-NULL-SHA256|TLSv1|Kx=RSA|Au=RSA|Enc=None|Mac=SHA256";
ciphers_desc["TLS1_RSA_WITH_AES_128_CBC_SHA256"]         = "RSA-AES128-SHA256|TLSv1|Kx=RSA|Au=RSA|Enc=AES-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_RSA_WITH_AES_256_CBC_SHA256"]         = "RSA-AES256-SHA256|TLSv1|Kx=RSA|Au=RSA|Enc=AES-CBC(256)|Mac=SHA256";
ciphers_desc["TLS1_DH_DSS_WITH_AES_128_CBC_SHA256"]      = "DH-DSS-AES128-SHA256|TLSv1|Kx=StaticDH|Au=DSS|Enc=AES-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_DH_RSA_WITH_AES_128_CBC_SHA256"]      = "DH-RSA-AES128-SHA256|TLSv1|Kx=StaticDH|Au=RSA|Enc=AES-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_DHE_DSS_WITH_AES_128_CBC_SHA256"]     = "DHE-DSS-AES128-SHA256|TLSv1|Kx=DH|Au=DSS|Enc=AES-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_DHE_RSA_WITH_AES_128_CBC_SHA256"]     = "DHE-RSA-AES128-SHA256|TLSv1|Kx=DH|Au=RSA|Enc=AES-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_DH_DSS_WITH_AES_256_CBC_SHA256"]      = "DH-DSS-AES256-SHA256|TLSv1|Kx=StaticDH|Au=DSS|Enc=AES-CBC(256)|Mac=SHA256";
ciphers_desc["TLS1_DH_RSA_WITH_AES_256_CBC_SHA256"]      = "DH-RSA-AES256-SHA256|TLSv1|Kx=StaticDH|Au=RSA|Enc=AES-CBC(256)|Mac=SHA256";
ciphers_desc["TLS1_DHE_DSS_WITH_AES_256_CBC_SHA256"]      = "DHE-DSS-AES256-SHA256|TLSv1|Kx=DH|Au=DSS|Enc=AES-CBC(256)|Mac=SHA256";
ciphers_desc["TLS1_DHE_RSA_WITH_AES_256_CBC_SHA256"]      = "DHE-RSA-AES256-SHA256|TLSv1|Kx=DH|Au=RSA|Enc=AES-CBC(256)|Mac=SHA256";
ciphers_desc["TLS1_DH_anon_WITH_AES_128_CBC_SHA256"]      = "DH-AES128-SHA256|TLSv1|Kx=DH|Au=None|Enc=AES-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_DH_anon_WITH_AES_256_CBC_SHA256"]      = "DH-AES256-SHA256|TLSv1|Kx=DH|Au=None|Enc=AES-CBC(256)|Mac=SHA256";
ciphers_desc["TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5"]   = "EXP1024-RC4-MD5|TLSv1|Kx=RSA(1024)|Au=RSA|Enc=RC4(56)|Mac=MD5|export";
ciphers_desc["TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5"]= "EXP1024-RC2-CBC-MD5|TLSv1|Kx=RSA(1024)|Au=RSA|Enc=RC2-CBC(56)|Mac=MD5|export";
ciphers_desc["TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA"]  = "EXP1024-DES-CBC-SHA|TLSv1|Kx=RSA(1024)|Au=RSA|Enc=DES-CBC(56)|Mac=SHA1|export";
ciphers_desc["TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"]= "EXP1024-DHE-DSS-DES-CBC-SHA|TLSv1|Kx=DH(1024)|Au=DSS|Enc=DES-CBC(56)|Mac=SHA1|export";
ciphers_desc["TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA"]   = "EXP1024-RC4-SHA|TLSv1|Kx=RSA(1024)|Au=RSA|Enc=RC4(56)|Mac=SHA1|export";
ciphers_desc["TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"]= "EXP1024-DHE-DSS-RC4-SHA|TLSv1|Kx=DH(1024)|Au=DSS|Enc=RC4(56)|Mac=SHA1|export";
ciphers_desc["TLS1_CK_DHE_DSS_WITH_RC4_128_SHA"]         = "DHE-DSS-RC4-SHA|TLSv1|Kx=DH|Au=DSS|Enc=RC4(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA"]    = "CAMELLIA128-SHA|TLSv1|Kx=RSA|Au=RSA|Enc=Camellia-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"] = "DH-DSS-CAMELLIA128-SHA|TLSv1|Kx=StaticDH|Au=DSS|Enc=Camellia-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"] = "DH-RSA-CAMELLIA128-SHA|TLSv1|Kx=StaticDH|Au=RSA|Enc=Camellia-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"]= "DHE-DSS-CAMELLIA128-SHA|TLSv1|Kx=DH|Au=DSS|Enc=Camellia-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"]= "DHE-RSA-CAMELLIA128-SHA|TLSv1|Kx=DH|Au=RSA|Enc=Camellia-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_anon_WITH_CAMELLIA_128_CBC_SHA"]= "ADH-CAMELLIA128-SHA|TLSv1|Kx=DH|Au=None|Enc=Camellia-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA"]    = "CAMELLIA256-SHA|TLSv1|Kx=RSA|Au=RSA|Enc=Camellia-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"] = "DH-DSS-CAMELLIA256-SHA|TLSv1|Kx=StaticDH|Au=DSS|Enc=Camellia-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"] = "DH-RSA-CAMELLIA256-SHA|TLSv1|Kx=StaticDH|Au=RSA|Enc=Camellia-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"]= "DHE-DSS-CAMELLIA256-SHA|TLSv1|Kx=DH|Au=DSS|Enc=Camellia-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"]= "DHE-RSA-CAMELLIA256-SHA|TLSv1|Kx=DH|Au=RSA|Enc=Camellia-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_anon_WITH_CAMELLIA_256_CBC_SHA"]= "ADH-CAMELLIA256-SHA|TLSv1|Kx=DH|Au=None|Enc=Camellia-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_GOSTR341094_WITH_28147_CNT_IMIT"]     = "GOST94-GOST89-GOST89|TLSv1|Kx=GOST|Au=GOST94|Enc=GOST2814789CNT(256)|Mac=GOST89MAC";
ciphers_desc["TLS1_GOSTR341001_WITH_28147_CNT_IMIT"]     = "GOST2001-GOST89-GOST89|TLSv1|Kx=GOST|Au=GOST01|Enc=GOST2814789CNT(256)|Mac=GOST89MAC";
ciphers_desc["TLS1_GOSTR341094_WITH_NULL_GOSTR3411"]     = "GOST94-NULL-GOST94|TLSv1|Kx=GOST|Au=GOST94|Enc=None|Mac=GOST94";
ciphers_desc["TLS1_GOSTR341001_WITH_NULL_GOSTR3411"]     = "GOST2001-NULL-GOST94|TLSv1|Kx=GOST|Au=GOST01|Enc=None|Mac=GOST94";
ciphers_desc["TLS1_CK_PSK_WITH_RC4_128_SHA"]             = "PSK-RC4-SHA|TLSv1|Kx=PSK|Au=PSK|Enc=RC4(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA"]        = "PSK-3DES-EDE-CBC-SHA|TLSv1|Kx=PSK|Au=PSK|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["TLS1_CK_PSK_WITH_AES_128_CBC_SHA"]         = "PSK-AES128-CBC-SHA|TLSv1|Kx=PSK|Au=PSK|Enc=AES-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_PSK_WITH_AES_256_CBC_SHA"]         = "PSK-AES256-CBC-SHA|TLSv1|Kx=PSK|Au=PSK|Enc=AES-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_CK_DHE_PSK_WITH_RC4_128_SHA"]         = "DHE-PSK-RC4128-SHA|TLSv1|Kx=DH|Au=PSK|Enc=RC4(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_DHE_PSK_WITH_3DES_EDE_CBC_SHA"]    = "DHE-PSK-3DES-CBC168-SHA|TLSv1|Kx=DH|Au=PSK|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA"]     = "DHE-PSK-AES128-SHA|TLSv1|Kx=DH|Au=PSK|Enc=AES-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA"]     = "DHE-PSK-AES256-SHA|TLSv1|Kx=DH|Au=PSK|Enc=AES-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_CK_RSA_PSK_WITH_RC4_128_SHA"]         = "RSA-PSK-RC4128-SHA|TLSv1|Kx=RSA|Au=PSK|Enc=RC4(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_RSA_PSK_WITH_3DES_EDE_CBC_SHA"]    = "RSA-PSK-3DES-CBC168-SHA|TLSv1|Kx=RSA|Au=PSK|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA"]     = "RSA-PSK-AES128-SHA|TLSv1|Kx=RSA|Au=PSK|Enc=AES-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA"]     = "RSA-PSK-AES256-SHA|TLSv1|Kx=RSA|Au=PSK|Enc=AES-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_CK_RSA_WITH_SEED_CBC_SHA"]            = "SEED-SHA|TLSv1|Kx=RSA|Au=RSA|Enc=SEED-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_DSS_WITH_SEED_CBC_SHA"]         = "DH-DSS-SEED-SHA|TLSv1|Kx=StaticDH|Au=DSS|Enc=SEED-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_RSA_WITH_SEED_CBC_SHA"]         = "DH-RSA-SEED-SHA|TLSv1|Kx=StaticDH|Au=RSA|Enc=SEED-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_DHE_DSS_WITH_SEED_CBC_SHA"]        = "DHE-DSS-SEED-SHA|TLSv1|Kx=DH|Au=DSS|Enc=SEED-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_DHE_RSA_WITH_SEED_CBC_SHA"]        = "DHE-RSA-SEED-SHA|TLSv1|Kx=DH|Au=RSA|Enc=SEED-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_DH_anon_WITH_SEED_CBC_SHA"]        = "ADH-SEED-SHA|TLSv1|Kx=DH|Au=None|Enc=SEED-CBC(128)|Mac=SHA1";
ciphers_desc["TLS12_PSK_WITH_AES_128_GCM_SHA256"]        = "PSK-AES128-SHA256|TLSv12|Kx=PSK|Au=PSK|Enc=AES-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_PSK_WITH_AES_256_GCM_SHA384"]        = "PSK-AES256-SHA384|TLSv12|Kx=PSK|Au=PSK|Enc=AES-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_DHE_PSK_WITH_AES_128_GCM_SHA256"]    = "DHE-PSK-AES128-SHA256|TLSv12|Kx=DH|Au=PSK|Enc=AES-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_DHE_PSK_WITH_AES_256_GCM_SHA384"]    = "DHE-PSK-AES256-SHA384|TLSv12|Kx=DH|Au=PSK|Enc=AES-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_RSA_PSK_WITH_AES_128_GCM_SHA256"]    = "RSA-PSK-AES128-SHA256|TLSv12|Kx=RSA|Au=PSK|Enc=AES-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_RSA_PSK_WITH_AES_256_GCM_SHA384"]    = "RSA-PSK-AES256-SHA384|TLSv12|Kx=RSA|Au=PSK|Enc=AES-GCM(256)|Mac=SHA384";
ciphers_desc["TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA"]         = "ECDH-ECDSA-NULL-SHA|TLSv1|Kx=StaticECDH|Au=ECDSA|Enc=None|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA"]      = "ECDH-ECDSA-RC4-SHA|TLSv1|Kx=StaticECDH|Au=ECDSA|Enc=RC4(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"] = "ECDH-ECDSA-DES-CBC3-SHA|TLSv1|Kx=StaticECDH|Au=ECDSA|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA"]  = "ECDH-ECDSA-AES128-SHA|TLSv1|Kx=StaticECDH|Au=ECDSA|Enc=AES-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA"]  = "ECDH-ECDSA-AES256-SHA|TLSv1|Kx=StaticECDH|Au=ECDSA|Enc=AES-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA"]        = "ECDHE-ECDSA-NULL-SHA|TLSv1|Kx=ECDH|Au=ECDSA|Enc=None|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA"]     = "ECDHE-ECDSA-RC4-SHA|TLSv1|Kx=ECDH|Au=ECDSA|Enc=RC4(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"]= "ECDHE-ECDSA-DES-CBC3-SHA|TLSv1|Kx=ECDH|Au=ECDSA|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"] = "ECDHE-ECDSA-AES128-SHA|TLSv1|Kx=ECDH|Au=ECDSA|Enc=AES-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"] = "ECDHE-ECDSA-AES256-SHA|TLSv1|Kx=ECDH|Au=ECDSA|Enc=AES-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDH_RSA_WITH_NULL_SHA"]           = "ECDH-RSA-NULL-SHA|TLSv1|Kx=StaticECDH|Au=RSA|Enc=None|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA"]        = "ECDH-RSA-RC4-SHA|TLSv1|Kx=StaticECDH|Au=RSA|Enc=RC4(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"]   = "ECDH-RSA-DES-CBC3-SHA|TLSv1|Kx=StaticECDH|Au=RSA|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA"]    = "ECDH-RSA-AES128-SHA|TLSv1|Kx=StaticECDH|Au=RSA|Enc=AES-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA"]    = "ECDH-RSA-AES256-SHA|TLSv1|Kx=StaticECDH|Au=RSA|Enc=AES-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDHE_RSA_WITH_NULL_SHA"]          = "ECDHE-RSA-NULL-SHA|TLSv1|Kx=ECDH|Au=RSA|Enc=None|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA"]       = "ECDHE-RSA-RC4-SHA|TLSv1|Kx=ECDH|Au=RSA|Enc=RC4(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"]  = "ECDHE-RSA-DES-CBC3-SHA|TLSv1|Kx=ECDH|Au=RSA|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA"]   = "ECDHE-RSA-AES128-SHA|TLSv1|Kx=ECDH|Au=RSA|Enc=AES-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA"]   = "ECDHE-RSA-AES256-SHA|TLSv1|Kx=ECDH|Au=RSA|Enc=AES-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDH_anon_NULL_WITH_SHA"]          = "AECDH-NULL-SHA|TLSv1|Kx=ECDH|Au=None|Enc=None|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDH_anon_WITH_RC4_128_SHA"]       = "AECDH-RC4-SHA|TLSv1|Kx=ECDH|Au=None|Enc=RC4(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDH_anon_WITH_3DES_EDE_CBC_SHA"]  = "AECDH-DES-CBC3-SHA|TLSv1|Kx=ECDH|Au=None|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA"]   = "AECDH-AES128-SHA|TLSv1|Kx=ECDH|Au=None|Enc=AES-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA"]   = "AECDH-AES256-SHA|TLSv1|Kx=ECDH|Au=None|Enc=AES-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_SRP_SHA_WITH_3DES_EDE_CBC_SHA"]       = "SRP-3DES168-SHA|TLSv1|Kx=SRP|Au=SHA|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["TLS1_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"]   = "SRP-RSA-3DES168-SHA|TLSv1|Kx=SRP|Au=SHA_RSA|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["TLS1_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"]   = "SRP-DSS-3DES168-SHA|TLSv1|Kx=SRP|Au=SHA_DSS|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["TLS1_SRP_SHA_WITH_AES_128_CBC_SHA"]        = "SRP-AES128-SHA|TLSv1|Kx=SRP|Au=SHA|Enc=AES-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"]    = "SRP-RSA-AES128-SHA|TLSv1|Kx=SRP|Au=SHA_RSA|Enc=AES-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"]    = "SRP-DSS-AES128-SHA|TLSv1|Kx=SRP|Au=SHA_DSS|Enc=AES-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_SRP_SHA_WITH_AES_256_CBC_SHA"]        = "SRP-AES256-SHA|TLSv1|Kx=SRP|Au=SHA|Enc=AES-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"]    = "SRP-RSA-AES256-SHA|TLSv1|Kx=SRP|Au=SHA_RSS|Enc=AES-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"]    = "SRP-DSS-AES256-SHA|TLSv1|Kx=SRP|Au=SHA_DSS|Enc=AES-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"] = "ECDHE-ECDSA-AES128-SHA256|TLSv1|Kx=ECDH|Au=ECDSA|Enc=AES-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"] = "ECDHE-ECDSA-AES256-SHA384|TLSv1|Kx=ECDH|Au=ECDSA|Enc=AES-CBC(256)|Mac=SHA384";
ciphers_desc["TLS1_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"]  = "ECDH-ECDSA-AES128-SHA256|TLSv1|Kx=StaticECDH|Au=ECDSA|Enc=AES-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"]  = "ECDH-ECDSA-AES256-SHA384|TLSv1|Kx=StaticECDH|Au=ECDSA|Enc=AES-CBC(256)|Mac=SHA384";
ciphers_desc["TLS1_ECDHE_RSA_WITH_AES_128_CBC_SHA256"]   = "ECDHE-RSA-AES128-SHA256|TLSv1|Kx=ECDH|Au=RSA|Enc=AES-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_ECDHE_RSA_WITH_AES_256_CBC_SHA384"]   = "ECDHE-RSA-AES256-SHA384|TLSv1|Kx=ECDH|Au=RSA|Enc=AES-CBC(256)|Mac=SHA384";
ciphers_desc["TLS1_ECDH_RSA_WITH_AES_128_CBC_SHA256"]    = "ECDH-RSA-AES128-SHA256|TLSv1|Kx=StaticECDH|Au=RSA|Enc=AES-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_ECDH_RSA_WITH_AES_256_CBC_SHA384"]    = "ECDH-RSA-AES256-SHA384|TLSv1|Kx=StaticECDH|Au=RSA|Enc=AES-CBC(256)|Mac=SHA384";
ciphers_desc["TLS1_ECDHE_PSK_WITH_RC4_128_SHA"]          = "ECDHE-PSK-RC4-128-SHA|TLSv1|Kx=ECDHE_PSK|Au=PSK|Enc=RC4(128)|Mac=SHA1";
ciphers_desc["TLS1_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"]     = "ECDHE-PSK-3DES168-SHA|TLSv1|Kx=ECDHE_PSK|Au=PSK|Enc=3DES-CBC(168)|Mac=SHA1";
ciphers_desc["TLS1_ECDHE_PSK_WITH_AES_128_CBC_SHA"]      = "ECDHE-PSK-AES128-SHA|TLSv1|Kx=ECDHE_PSK|Au=PSK|Enc=AES-CBC(128)|Mac=SHA1";
ciphers_desc["TLS1_ECDHE_PSK_WITH_AES_256_CBC_SHA"]      = "ECDHE-PSK-AES256-SHA|TLSv1|Kx=ECDHE_PSK|Au=PSK|Enc=AES-CBC(256)|Mac=SHA1";
ciphers_desc["TLS1_ECDHE_PSK_WITH_AES_128_CBC_SHA256"]   = "ECDHE-PSK-AES128-SHA256|TLSv1|Kx=ECDHE_PSK|Au=PSK|Enc=AES-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_ECDHE_PSK_WITH_AES_256_CBC_SHA384"]   = "ECDHE-PSK-AES256-SHA384|TLSv1|Kx=ECDHE_PSK|Au=PSK|Enc=AES-CBC(256)|Mac=SHA384";
ciphers_desc["TLS1_ECDHE_PSK_WITH_NULL_SHA"]             = "ECDHE-PSK-NULL-SHA|TLSv1|Kx=ECDHE_PSK|Au=PSK|Enc=None|Mac=SHA1";
ciphers_desc["TLS1_ECDHE_PSK_WITH_NULL_SHA256"]          = "ECDHE-PSK-NULL-SHA256|TLSv1|Kx=ECDHE_PSK|Au=PSK|Enc=None|Mac=SHA256";
ciphers_desc["TLS1_ECDHE_PSK_WITH_NULL_SHA384"]          = "ECDHE-PSK-NULL-SHA384|TLSv1|Kx=ECDHE_PSK|Au=PSK|Enc=None|Mac=SHA384";
ciphers_desc["TLS12_RSA_WITH_AES_128_GCM_SHA256"]        = "RSA-AES128-SHA256|TLSv12|Kx=RSA|Au=RSA|Enc=AES-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_RSA_WITH_AES_256_GCM_SHA384"]        = "RSA-AES256-SHA384|TLSv12|Kx=RSA|Au=RSA|Enc=AES-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_DHE_RSA_WITH_AES_128_GCM_SHA256"]    = "DHE-RSA-AES128-SHA256|TLSv12|Kx=DH|Au=RSA|Enc=AES-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_DHE_RSA_WITH_AES_256_GCM_SHA384"]    = "DHE-RSA-AES256-SHA384|TLSv12|Kx=DH|Au=RSA|Enc=AES-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_DH_RSA_WITH_AES_128_GCM_SHA256"]     = "DH-RSA-AES128-SHA256|TLSv12|Kx=StaticDH|Au=RSA|Enc=AES-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_DH_RSA_WITH_AES_256_GCM_SHA384"]     = "DH-RSA-AES256-SHA384|TLSv12|Kx=StaticDH|Au=RSA|Enc=AES-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_DHE_DSS_WITH_AES_128_GCM_SHA256"]    = "DHE-DSS-AES128-SHA256|TLSv12|Kx=DH|Au=DSS|Enc=AES-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_DHE_DSS_WITH_AES_256_GCM_SHA384"]    = "DHE-DSS-AES256-SHA384|TLSv12|Kx=DH|Au=DSS|Enc=AES-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_DH_DSS_WITH_AES_128_GCM_SHA256"]     = "DH-DSS-AES128-SHA256|TLSv12|Kx=StaticDH|Au=DSS|Enc=AES-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_DH_DSS_WITH_AES_256_GCM_SHA384"]     = "DH-DSS-AES256-SHA384|TLSv12|Kx=StaticDH|Au=DSS|Enc=AES-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_DH_anon_WITH_AES_128_GCM_SHA256"]    = "DH-AES128-SHA256|TLSv12|Kx=DH|Au=None|Enc=AES-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_DH_anon_WITH_AES_256_GCM_SHA384"]    = "DH-AES256-SHA384|TLSv12|Kx=DH|Au=None|Enc=AES-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"]= "ECDHE-ECDSA-AES128-SHA256|TLSv12|Kx=ECDH|Au=ECDSA|Enc=AES-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"]= "ECDHE-ECDSA-AES256-SHA384|TLSv12|Kx=ECDH|Au=ECDSA|Enc=AES-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"] = "ECDH-ECDSA-AES128-SHA256|TLSv12|Kx=StaticECDH|Au=ECDSA|Enc=AES-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"] = "ECDH-ECDSA-AES256-SHA384|TLSv12|Kx=StaticECDH|Au=ECDSA|Enc=AES-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]  = "ECDHE-RSA-AES128-SHA256|TLSv12|Kx=ECDH|Au=RSA|Enc=AES-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]  = "ECDHE-RSA-AES256-SHA384|TLSv12|Kx=ECDH|Au=RSA|Enc=AES-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_ECDH_RSA_WITH_AES_128_GCM_SHA256"]   = "ECDH-RSA-AES128-SHA256|TLSv12|Kx=StaticECDH|Au=RSA|Enc=AES-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_ECDH_RSA_WITH_AES_256_GCM_SHA384"]   = "ECDH-RSA-AES256-SHA384|TLSv12|Kx=StaticECDH|Au=RSA|Enc=AES-GCM(256)|Mac=SHA384";
ciphers_desc["TLS1_PSK_WITH_AES_128_CBC_SHA256"]         = "PSK-AES128-SHA256|TLSv1|Kx=PSK|Au=PSK|Enc=AES-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_PSK_WITH_AES_256_CBC_SHA384"]         = "PSK-AES256-SHA384|TLSv1|Kx=PSK|Au=PSK|Enc=AES-CBC(256)|Mac=SHA384";
ciphers_desc["TLS1_PSK_WITH_NULL_SHA256"]                = "PSK-NULL-SHA256|TLSv1|Kx=PSK|Au=PSK|Enc=None|Mac=SHA256";
ciphers_desc["TLS1_PSK_WITH_NULL_SHA384"]                = "PSK-NULL-SHA384|TLSv1|Kx=PSK|Au=PSK|Enc=None|Mac=SHA384";
ciphers_desc["TLS1_DHE_PSK_WITH_AES_128_CBC_SHA256"]     = "DHE-PSK-AES128-SHA256|TLSv1|Kx=DH|Au=PSK|Enc=AES-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_DHE_PSK_WITH_AES_256_CBC_SHA384"]     = "DHE-PSK-AES256-SHA384|TLSv1|Kx=DH|Au=PSK|Enc=AES-CBC(256)|Mac=SHA384";
ciphers_desc["TLS1_DHE_PSK_WITH_NULL_SHA256"]            = "DHE-PSK-NULL-SHA256|TLSv1|Kx=DH|Au=PSK|Enc=None|Mac=SHA256";
ciphers_desc["TLS1_DHE_PSK_WITH_NULL_SHA384"]            = "DHE-PSK-NULL-SHA384|TLSv1|Kx=DH|Au=PSK|Enc=None|Mac=SHA384";
ciphers_desc["TLS1_RSA_PSK_WITH_AES_128_CBC_SHA256"]     = "RSA-PSK-AES128-SHA256|TLSv1|Kx=RSA|Au=PSK|Enc=AES-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_RSA_PSK_WITH_AES_256_CBC_SHA384"]     = "RSA-PSK-AES256-SHA384|TLSv1|Kx=RSA|Au=PSK|Enc=AES-CBC(256)|Mac=SHA384";
ciphers_desc["TLS1_RSA_PSK_WITH_NULL_SHA256"]            = "RSA-PSK-NULL-SHA256|TLSv1|Kx=RSA|Au=PSK|Enc=None|Mac=SHA256";
ciphers_desc["TLS1_RSA_PSK_WITH_NULL_SHA384"]            = "RSA-PSK-NULL-SHA384|TLSv1|Kx=RSA|Au=PSK|Enc=None|Mac=SHA384";
ciphers_desc["TLS1_RSA_WITH_CAMELLIA_128_CBC_SHA256"]    = "RSA-CAMELLIA128-SHA256|TLSv1|Kx=RSA|Au=RSA|Enc=Camellia-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"] = "DH-DSS-CAMELLIA128-SHA256|TLSv1|Kx=StaticDH|Au=DSS|Enc=Camellia-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"] = "DH-RSA-CAMELLIA128-SHA256|TLSv1|Kx=StaticDH|Au=RSA|Enc=Camellia-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"]= "DHE-DSS-CAMELLIA128-SHA256|TLSv1|Kx=DH|Au=DSS|Enc=Camellia-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"]= "DHE-RSA-CAMELLIA128-SHA256|TLSv1|Kx=DH|Au=RSA|Enc=Camellia-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"]= "DH-CAMELLIA128-SHA256|TLSv1|Kx=DH|Au=None|Enc=Camellia-CBC(128)|Mac=SHA256";
ciphers_desc["TLS1_RSA_WITH_CAMELLIA_256_CBC_SHA256"]    = "RSA-CAMELLIA256-SHA256|TLSv1|Kx=RSA|Au=RSA|Enc=Camellia-CBC(256)|Mac=SHA256";
ciphers_desc["TLS1_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"] = "DH-DSS-CAMELLIA256-SHA256|TLSv1|Kx=StaticDH|Au=DSS|Enc=Camellia-CBC(256)|Mac=SHA256";
ciphers_desc["TLS1_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"] = "DH-RSA-CAMELLIA256-SHA256|TLSv1|Kx=StaticDH|Au=RSA|Enc=Camellia-CBC(256)|Mac=SHA256";
ciphers_desc["TLS1_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"]= "DHE-DSS-CAMELLIA256-SHA256|TLSv1|Kx=DH|Au=DSS|Enc=Camellia-CBC(256)|Mac=SHA256";
ciphers_desc["TLS1_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"]= "DHE-RSA-CAMELLIA256-SHA256|TLSv1|Kx=DH|Au=RSA|Enc=Camellia-CBC(256)|Mac=SHA256";
ciphers_desc["TLS1_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"]= "DH-CAMELLIA256-SHA256|TLSv1|Kx=DH|Au=None|Enc=Camellia-CBC(256)|Mac=SHA256";
# RFC 6367
ciphers_desc["TLS12_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"] = "ECDHE-ECDSA-CAMELLIA-CBC-128|TLSv12|Kx=ECDH|Au=ECDSA|Enc=Camellia-CBC(128)|Mac=SHA256";
ciphers_desc["TLS12_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"] = "ECDHE-ECDSA-CAMELLIA-CBC-256|TLSv12|Kx=ECDH|Au=ECDSA|Enc=Camellia-CBC(256)|Mac=SHA384";
ciphers_desc["TLS12_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"]  = "ECDH-ECDSA-CAMELLIA-CBC-128|TLSv12|Kx=StaticECDH|Au=ECDSA|Enc=Camellia-CBC(128)|Mac=SHA256";
ciphers_desc["TLS12_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"]  = "ECDH-ECDSA-CAMELLIA-CBC-256|TLSv12|Kx=StaticECDH|Au=ECDSA|Enc=Camellia-CBC(256)|Mac=SHA384";
ciphers_desc["TLS12_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"]   = "ECDHE-RSA-CAMELLIA-CBC-128|TLSv12|Kx=ECDH|Au=RSA|Enc=Camellia-CBC(128)|Mac=SHA256";
ciphers_desc["TLS12_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"]   = "ECDHE-RSA-CAMELLIA-CBC-256|TLSv12|Kx=ECDH|Au=RSA|Enc=Camellia-CBC(256)|Mac=SHA384";
ciphers_desc["TLS12_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"]    = "ECDH-RSA-CAMELLIA-CBC-128|TLSv12|Kx=StaticECDH|Au=RSA|Enc=Camellia-CBC(128)|Mac=SHA256";
ciphers_desc["TLS12_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"]    = "ECDH-RSA-CAMELLIA-CBC-256|TLSv12|Kx=StaticECDH|Au=RSA|Enc=Camellia-CBC(256)|Mac=SHA384";
ciphers_desc["TLS12_RSA_WITH_CAMELLIA_128_GCM_SHA256"]         = "RSA-CAMELLIA-GCM-128|TLSv12|Kx=RSA|Au=RSA|Enc=Camellia-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_RSA_WITH_CAMELLIA_256_GCM_SHA384"]         = "RSA-CAMELLIA-GCM-256|TLSv12|Kx=RSA|Au=RSA|Enc=Camellia-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"]     = "DHE-RSA-CAMELLIA-GCM-128|TLSv12|Kx=DH|Au=RSA|Enc=Camellia-GCM(256)|Mac=SHA256";
ciphers_desc["TLS12_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"]     = "DHE-RSA-CAMELLIA-GCM-256|TLSv12|Kx=DH|Au=RSA|Enc=Camellia-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256"]      = "DH-RSA-CAMELLIA-GCM-128|TLSv12|Kx=StaticDH|Au=RSA|Enc=Camellia-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384"]      = "DH-RSA-CAMELLIA-GCM-256|TLSv12|Kx=StaticDH|Au=RSA|Enc=Camellia-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"]     = "DHE-DSS-CAMELLIA-GCM-128|TLSv12|Kx=DH|Au=DSS|Enc=Camellia-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384"]     = "DHE-DSS-CAMELLIA-GCM-256|TLSv12|Kx=DH|Au=DSS|Enc=Camellia-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256"]      = "DH-DSS-CAMELLIA-GCM-128|TLSv12|Kx=StaticDH|Au=DSS|Enc=Camellia-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384"]      = "DH-DSS-CAMELLIA-GCM-256|TLSv12|Kx=StaticDH|Au=DSS|Enc=Camellia-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_DH_anon_WITH_CAMELLIA_128_GCM_SHA256"]     = "DH-CAMELLIA-GCM-128|TLSv12|Kx=DH|Au=None|Enc=Camellia-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_DH_anon_WITH_CAMELLIA_256_GCM_SHA384"]     = "DH-CAMELLIA-GCM-256|TLSv12|Kx=DH|Au=None|Enc=Camellia-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"] = "ECDHE-ECDSA-CAMELLIA-GCM-128|TLSv12|Kx=ECDH|Au=ECDSA|Enc=Camellia-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"] = "ECDHE-ECDSA-CAMELLIA-GCM-256|TLSv12|Kx=ECDH|Au=ECDSA|Enc=Camellia-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"]  = "ECDH-ECDSA-CAMELLIA-GCM-128|TLSv12|Kx=StaticECDH|Au=ECDSA|Enc=Camellia-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"]  = "ECDH-ECDSA-CAMELLIA-GCM-256|TLSv12|Kx=StaticECDH|Au=ECDSA|Enc=Camellia-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"]   = "ECDHE-RSA-CAMELLIA-GCM-128|TLSv12|Kx=ECDH|Au=RSA|Enc=Camellia-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"]   = "ECDHE-RSA-CAMELLIA-GCM-256|TLSv12|Kx=ECDH|Au=RSA|Enc=Camellia-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256"]    = "ECDH-RSA-CAMELLIA-GCM-128|TLSv12|Kx=StaticECDH|Au=RSA|Enc=Camellia-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384"]    = "ECDH-RSA-CAMELLIA-GCM-256|TLSv12|Kx=StaticECDH|Au=RSA|Enc=Camellia-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_PSK_WITH_CAMELLIA_128_GCM_SHA256"]          = "PSK-CAMELLIA-GCM-128|TLSv12|Kx=PSK|Au=PSK|Enc=Camellia-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_PSK_WITH_CAMELLIA_256_GCM_SHA384"]          = "PSK-CAMELLIA-GCM-256|TLSv12|Kx=PSK|Au=PSK|Enc=Camellia-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256"]      = "DHE-PSK-CAMELLIA-GCM-128|TLSv12|Kx=DH|Au=PSK|Enc=Camellia-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384"]      = "DHE-PSK-CAMELLIA-GCM-256|TLSv12|Kx=DH|Au=PSK|Enc=Camellia-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256"]      = "RSA-PSK-CAMELLIA-GCM-128|TLSv12|Kx=RSA|Au=PSK|Enc=Camellia-GCM(128)|Mac=SHA256";
ciphers_desc["TLS12_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384"]      = "RSA-PSK-CAMELLIA-GCM-256|TLSv12|Kx=RSA|Au=PSK|Enc=Camellia-GCM(256)|Mac=SHA384";
ciphers_desc["TLS12_PSK_WITH_CAMELLIA_128_CBC_SHA256"]          = "PSK-CAMELLIA-GCM-128|TLSv12|Kx=PSK|Au=PSK|Enc=Camellia-CBC(128)|Mac=SHA256";
ciphers_desc["TLS12_PSK_WITH_CAMELLIA_256_CBC_SHA384"]          = "PSK-CAMELLIA-GCM-256|TLSv12|Kx=PSK|Au=PSK|Enc=Camellia-CBC(256)|Mac=SHA384";
ciphers_desc["TLS12_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"]      = "DHE-PSK-CAMELLIA-GCM-128|TLSv12|Kx=DH|Au=PSK|Enc=Camellia-CBC(128)|Mac=SHA256";
ciphers_desc["TLS12_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"]      = "DHE-PSK-CAMELLIA-GCM-256|TLSv12|Kx=DH|Au=PSK|Enc=Camellia-CBC(256)|Mac=SHA384";
ciphers_desc["TLS12_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"]      = "RSA-PSK-CAMELLIA-GCM-128|TLSv12|Kx=RSA|Au=PSK|Enc=Camellia-CBC(128)|Mac=SHA256";
ciphers_desc["TLS12_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"]      = "RSA-PSK-CAMELLIA-GCM-256|TLSv12|Kx=RSA|Au=PSK|Enc=Camellia-CBC(256)|Mac=SHA384";
ciphers_desc["TLS12_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"]    = "ECDHE-PSK-CAMELLIA-GCM-128|TLSv12|Kx=ECDHE_PSK|Au=PSK|Enc=Camellia-CBC(128)|Mac=SHA256";
ciphers_desc["TLS12_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"]    = "ECDHE-PSK-CAMELLIA-GCM-256|TLSv12|Kx=ECDHE_PSK|Au=PSK|Enc=Camellia-CBC(256)|Mac=SHA384";
# RFC 6655 
ciphers_desc["TLS12_RSA_WITH_AES_128_CCM"]                      = "n/a|TLSv12|Kx=RSA|Au=RSA|Enc=AES-CCM(128)|Mac=AEAD";
ciphers_desc["TLS12_RSA_WITH_AES_256_CCM"]                      = "n/a|TLSv12|Kx=RSA|Au=RSA|Enc=AES-CCM(256)|Mac=AEAD";
ciphers_desc["TLS12_DHE_RSA_WITH_AES_128_CCM"]                  = "n/a|TLSv12|Kx=DH|Au=RSA|Enc=AES-CCM(128)|Mac=AEAD";
ciphers_desc["TLS12_DHE_RSA_WITH_AES_256_CCM"]                  = "n/a|TLSv12|Kx=DH|Au=RSA|Enc=AES-CCM(256)|Mac=AEAD";
ciphers_desc["TLS12_RSA_WITH_AES_128_CCM_8"]                    = "n/a|TLSv12|Kx=RSA|Au=RSA|Enc=AES-CCM8(128)|Mac=AEAD";
ciphers_desc["TLS12_RSA_WITH_AES_256_CCM_8"]                    = "n/a|TLSv12|Kx=RSA|Au=RSA|Enc=AES-CCM8(256)|Mac=AEAD"; 
ciphers_desc["TLS12_DHE_RSA_WITH_AES_128_CCM_8"]                = "n/a|TLSv12|Kx=DH|Au=RSA|Enc=AES-CCM8(128)|Mac=AEAD";
ciphers_desc["TLS12_DHE_RSA_WITH_AES_256_CCM_8"]                = "n/a|TLSv12|Kx=DH|Au=RSA|Enc=AES-CCM8(256)|Mac=AEAD";
ciphers_desc["TLS12_PSK_WITH_AES_128_CCM"]                      = "n/a|TLSv12|Kx=PSK|Au=PSK|Enc=AES-CCM(128)|Mac=AEAD"; 
ciphers_desc["TLS12_PSK_WITH_AES_256_CCM"]                      = "n/a|TLSv12|Kx=PSK|Au=PSK|Enc=AES-CCM(256)|Mac=AEAD";  
ciphers_desc["TLS12_DHE_PSK_WITH_AES_128_CCM"]                  = "n/a|TLSv12|Kx=DH|Au=PSK|Enc=AES-CCM(128)|Mac=AEAD";   
ciphers_desc["TLS12_DHE_PSK_WITH_AES_256_CCM"]                  = "n/a|TLSv12|Kx=DH|Au=PSK|Enc=AES-CCM(256)|Mac=AEAD";   
ciphers_desc["TLS12_PSK_WITH_AES_128_CCM_8"]                    = "n/a|TLSv12|Kx=PSK|Au=PSK|Enc=AES-CCM8(128)|Mac=AEAD"; 
ciphers_desc["TLS12_PSK_WITH_AES_256_CCM_8"]                    = "n/a|TLSv12|Kx=PSK|Au=PSK|Enc=AES-CCM8(256)|Mac=AEAD"; 
ciphers_desc["TLS12_PSK_DHE_WITH_AES_128_CCM_8"]                = "n/a|TLSv12|Kx=DH|Au=PSK|Enc=AES-CCM8(128)|Mac=AEAD";   
ciphers_desc["TLS12_PSK_DHE_WITH_AES_256_CCM_8"]                = "n/a|TLSv12|Kx=DH|Au=PSK|Enc=AES-CCM8(256)|Mac=AEAD";   
ciphers_desc["TLS12_ECDHE_ECDSA_WITH_AES_128_CCM"]              = "n/a|TLSv12|Kx=ECDH|Au=ECDSA|Enc=AES-CCM(128)|Mac=AEAD";   
ciphers_desc["TLS12_ECDHE_ECDSA_WITH_AES_256_CCM"]              = "n/a|TLSv12|Kx=ECDH|Au=ECDSA|Enc=AES-CCM(256)|Mac=AEAD";   
ciphers_desc["TLS12_ECDHE_ECDSA_WITH_AES_128_CCM_8"]            = "n/a|TLSv12|Kx=ECDH|Au=ECDSA|Enc=AES-CCM8(128)|Mac=AEAD";   
ciphers_desc["TLS12_ECDHE_ECDSA_WITH_AES_256_CCM_8"]            = "n/a|TLSv12|Kx=ECDH|Au=ECDSA|Enc=AES-CCM8(256)|Mac=AEAD";    
# RFC 7251
ciphers_desc["TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"]     = "ECDHE-RSA-CHACHA20-POLY1305|TLSv12|Kx=ECDH|Au=RSA|Enc=ChaCha20-Poly1305(256)|Mac=SHA256";
ciphers_desc["TLS12_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"]   = "ECDHE-ECDSA-CHACHA20-POLY1305|TLSv12|Kx=ECDH|Au=ECDSA|Enc=ChaCha20-Poly1305(256)|Mac=SHA256";
ciphers_desc["TLS12_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"]       = "DHE-RSA-CHACHA20-POLY1305|TLSv12|Kx=DH|Au=RSA|Enc=ChaCha20-Poly1305(256)|Mac=SHA256";
ciphers_desc["TLS12_PSK_WITH_CHACHA20_POLY1305_SHA256"]           = "PSK-CHACHA20-POLY1305|TLSv12|Kx=PSK|Au=PSK|Enc=ChaCha20-Poly1305(256)|Mac=SHA256";
ciphers_desc["TLS12_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"]     = "ECDHE-PSK-CHACHA20-POLY1305|TLSv12|Kx=ECDHE_PSK|Au=PSK|Enc=ChaCha20-Poly1305(256)|Mac=SHA256";
ciphers_desc["TLS12_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"]       = "DHE-PSK-CHACHA20-POLY1305|TLSv12|Kx=DH|Au=PSK|Enc=ChaCha20-Poly1305(256)|Mac=SHA256";
ciphers_desc["TLS12_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"]       = "RSA-PSK-CHACHA20-POLY1305|TLSv12|Kx=RSA|Au=PSK|Enc=ChaCha20-Poly1305(256)|Mac=SHA256";
# Other ciphers not in IANA registry
ciphers_desc["SSL3_FORTEZZA_KEA_WITH_NULL_SHA"]                 = "n/a|SSLv3|Kx=FORTEZZA-KEA|Au=FORTEZZA|Enc=NULL|Mac=SHA1";    
ciphers_desc["SSL3_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA"]         = "n/a|SSLv3|Kx=FORTEZZA-KEA|Au=FORTEZZA|Enc=FORTEZZA-CBC|Mac=SHA1";     
# http://www-archive.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
ciphers_desc["SSL3_RSA_FIPS_WITH_DES_CBC_SHA"]                  = "DES-CBC-SHA(FIPS)|SSLv3|Kx=RSA|Au=RSA|Enc=DES-CBC(56)|Mac=SHA1";      
ciphers_desc["SSL3_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"]             = "DES-CBC3-SHA(FIPS)|SSLv3|Kx=RSA|Au=RSA|Enc=3DES-CBC(168)|Mac=SHA1";      
ciphers_desc["SSL3_RSA_FIPS_WITH_DES_CBC_SHA_PRIVATE"]          = "DES-CBC-SHA(FIPS, private)|SSLv3|Kx=RSA|Au=RSA|Enc=DES-CBC(56)|Mac=SHA1";      
ciphers_desc["SSL3_RSA_FIPS_WITH_3DES_EDE_CBC_SHA_PRIVATE"]     = "DES-CBC3-SHA(FIPS, private)|SSLv3|Kx=RSA|Au=RSA|Enc=3DES-CBC(168)|Mac=SHA1";      

# From https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml and RFC4492
global_var elliptic_curves;
elliptic_curves["CURVE_SECT163K1"] = raw_string(0, 1);
elliptic_curves["CURVE_SECT163R1"] = raw_string(0, 2);
elliptic_curves["CURVE_SECT163R2"] = raw_string(0, 3);
elliptic_curves["CURVE_SECT193R1"] = raw_string(0, 4);
elliptic_curves["CURVE_SECT193R2"] = raw_string(0, 5);
elliptic_curves["CURVE_SECT233K1"] = raw_string(0, 6);
elliptic_curves["CURVE_SECT233R1"] = raw_string(0, 7);
elliptic_curves["CURVE_SECT239K1"] = raw_string(0, 8);
elliptic_curves["CURVE_SECT283K1"] = raw_string(0, 9);
elliptic_curves["CURVE_SECT283R1"] = raw_string(0, 10);
elliptic_curves["CURVE_SECT409K1"] = raw_string(0, 11);
elliptic_curves["CURVE_SECT409R1"] = raw_string(0, 12);
elliptic_curves["CURVE_SECT571K1"] = raw_string(0, 13);
elliptic_curves["CURVE_SECT571R1"] = raw_string(0, 14);
elliptic_curves["CURVE_SECP160K1"] = raw_string(0, 15);
elliptic_curves["CURVE_SECP160R1"] = raw_string(0, 16);
elliptic_curves["CURVE_SECP160R2"] = raw_string(0, 17);
elliptic_curves["CURVE_SECP192K1"] = raw_string(0, 18);
elliptic_curves["CURVE_SECP192R1"] = raw_string(0, 19);
elliptic_curves["CURVE_SECP224K1"] = raw_string(0, 20);
elliptic_curves["CURVE_SECP224R1"] = raw_string(0, 21);
elliptic_curves["CURVE_SECP256K1"] = raw_string(0, 22);
elliptic_curves["CURVE_SECP256R1"] = raw_string(0, 23);
elliptic_curves["CURVE_SECP384R1"] = raw_string(0, 24);
elliptic_curves["CURVE_SECP521R1"] = raw_string(0, 25);

##
# This is the list of all compression methods available in SSL / TLS.
##
global_var compressors;

compressors = make_array(
  0x00, "NULL",
  0x01, "DEFLATE",
  0x40, "LZS"
);

# As a transitional measure, the following encapsulation
# specifications will add basic support for newer versions of TLS.
# Support added in Nessus 6.4
global_var COMPAT_ENCAPS_TLSv11, COMPAT_ENCAPS_TLSv12, COMPAT_ENCAPS_TEST, COMPAT_ENCAPS_DISABLE_TLSv1_2, COMPAT_ENCAPS_DISABLE_TLSv1_1, COMPAT_ENCAPS_DISABLE_TLSv1, COMPAT_ENCAPS_DISABLE_SSLv3, COMPAT_ENCAPS_DISABLE_SSLv2;

if (ENCAPS_TLSv11)
  COMPAT_ENCAPS_TLSv11 = ENCAPS_TLSv11;
else
  COMPAT_ENCAPS_TLSv11 = 6;

if (ENCAPS_TLSv12)
  COMPAT_ENCAPS_TLSv12 = ENCAPS_TLSv12;
else
  COMPAT_ENCAPS_TLSv12 = 7;

if (ENCAPS_DISABLE_SSLv2)
  COMPAT_ENCAPS_DISABLE_SSLv2 = ENCAPS_DISABLE_SSLv2;
else
  COMPAT_ENCAPS_DISABLE_SSLv2 = NULL;

if (ENCAPS_DISABLE_SSLv3)
  COMPAT_ENCAPS_DISABLE_SSLv3 = ENCAPS_DISABLE_SSLv3;
else
  COMPAT_ENCAPS_DISABLE_SSLv3 = NULL;

if (ENCAPS_DISABLE_TLSv1)
  COMPAT_ENCAPS_DISABLE_TLSv1 = ENCAPS_DISABLE_TLSv1;
else
  COMPAT_ENCAPS_DISABLE_TLSv1 = NULL;

if (ENCAPS_DISABLE_TLSv1_1)
  COMPAT_ENCAPS_DISABLE_TLSv1_1 = ENCAPS_DISABLE_TLSv1_1;
else
  COMPAT_ENCAPS_DISABLE_TLSv1_1 = NULL;

if (ENCAPS_DISABLE_TLSv1_2)
  COMPAT_ENCAPS_DISABLE_TLSv1_2 = ENCAPS_DISABLE_TLSv1_2;
else
  COMPAT_ENCAPS_DISABLE_TLSv1_2 = NULL;


# Define the IDs for the different versions of SSL/TLS.
global_var SSL_V2, SSL_V3, TLS_10, TLS_11, TLS_12;

SSL_V2 = 0x0002;
SSL_V3 = 0x0300;
TLS_10 = 0x0301;
TLS_11 = 0x0302;
TLS_12 = 0x0303;

global_var
  SSL2_CONTENT_TYPE_ERROR,
  SSL2_CONTENT_TYPE_CLIENT_HELLO,
  SSL2_CONTENT_TYPE_CLIENT_MASTER_KEY,
  SSL2_CONTENT_TYPE_CLIENT_FINISHED,
  SSL2_CONTENT_TYPE_SERVER_HELLO,
  SSL2_CONTENT_TYPE_SERVER_VERIFY,
  SSL2_CONTENT_TYPE_SERVER_FINISHED,
  SSL2_CONTENT_TYPE_REQUEST_CERTIFICATE,
  SSL2_CONTENT_TYPE_CLIENT_CERTIFICATE;

SSL2_CONTENT_TYPE_ERROR = 0;
SSL2_CONTENT_TYPE_CLIENT_HELLO = 1;
SSL2_CONTENT_TYPE_CLIENT_MASTER_KEY = 2;
SSL2_CONTENT_TYPE_CLIENT_FINISHED = 3;
SSL2_CONTENT_TYPE_SERVER_HELLO = 4;
SSL2_CONTENT_TYPE_SERVER_VERIFY = 5;
SSL2_CONTENT_TYPE_SERVER_FINISHED = 6;
SSL2_CONTENT_TYPE_REQUEST_CERTIFICATE = 7;
SSL2_CONTENT_TYPE_CLIENT_CERTIFICATE = 8;

global_var
  SSL3_CONTENT_TYPE_CHANGECIPHERSPEC,
  SSL3_CONTENT_TYPE_ALERT,
  SSL3_CONTENT_TYPE_HANDSHAKE,
  SSL3_CONTENT_TYPE_APPLICATION_DATA;

SSL3_CONTENT_TYPE_CHANGECIPHERSPEC = 20;
SSL3_CONTENT_TYPE_ALERT = 21;
SSL3_CONTENT_TYPE_HANDSHAKE = 22;
SSL3_CONTENT_TYPE_APPLICATION_DATA = 23;

global_var
  SSL3_ALERT_TYPE_CLOSE_NOTIFY,
  SSL3_ALERT_TYPE_WARNING,
  SSL3_ALERT_TYPE_FATAL,
  SSL3_ALERT_TYPE_UNEXPECTED_MESSAGE,
  SSL3_ALERT_TYPE_BAD_RECORD_MAC,
  SSL3_ALERT_TYPE_DECRYPTION_FAILED,
  SSL3_ALERT_TYPE_RECORD_OVERFLOW,
  SSL3_ALERT_TYPE_DECOMPRESSION_FAILURE,
  SSL3_ALERT_TYPE_HANDSHAKE_FAILURE,
  SSL3_ALERT_TYPE_BAD_CERTIFICATE,
  SSL3_ALERT_TYPE_UNSUPPORTED_CERTIFICATE,
  SSL3_ALERT_TYPE_CERTIFICATE_REVOKED,
  SSL3_ALERT_TYPE_CERTIFICATE_EXPIRED,
  SSL3_ALERT_TYPE_CERTIFICATE_UNKNOWN,
  SSL3_ALERT_TYPE_ILLEGAL_PARAMETER,
  SSL3_ALERT_TYPE_UNKNOWN_CA,
  SSL3_ALERT_TYPE_ACCESS_DENIED,
  SSL3_ALERT_TYPE_DECODE_ERROR,
  SSL3_ALERT_TYPE_DECRYPT_ERROR,
  SSL3_ALERT_TYPE_EXPORT_RESTRICTION,
  SSL3_ALERT_TYPE_INAPPROPRIATE_FALLBACK,
  SSL3_ALERT_TYPE_PROTOCOL_VERSION,
  SSL3_ALERT_TYPE_INSUFFICIENT_SECURITY,
  SSL3_ALERT_TYPE_INTERNAL_ERROR,
  SSL3_ALERT_TYPE_USER_CANCELED,
  SSL3_ALERT_TYPE_NO_RENEGOTIATION,
  SSL3_ALERT_TYPE_UNSUPPORTED_EXTENSION,
  SSL3_ALERT_TYPE_CERTIFICATE_UNOBTAINABLE,
  SSL3_ALERT_TYPE_UNRECOGNIZED_NAME,
  SSL3_ALERT_TYPE_BAD_CERTIFICATE_STATUS_RESPONSE,
  SSL3_ALERT_TYPE_BAD_CERTIFICATE_HASH_VALUE;

SSL3_ALERT_TYPE_CLOSE_NOTIFY = 0;
SSL3_ALERT_TYPE_WARNING = 1;
SSL3_ALERT_TYPE_FATAL = 2;
SSL3_ALERT_TYPE_UNEXPECTED_MESSAGE = 10;
SSL3_ALERT_TYPE_BAD_RECORD_MAC = 20;
SSL3_ALERT_TYPE_DECRYPTION_FAILED = 21;
SSL3_ALERT_TYPE_RECORD_OVERFLOW = 22;
SSL3_ALERT_TYPE_DECOMPRESSION_FAILURE = 30;
SSL3_ALERT_TYPE_HANDSHAKE_FAILURE = 40;
SSL3_ALERT_TYPE_BAD_CERTIFICATE = 42;
SSL3_ALERT_TYPE_UNSUPPORTED_CERTIFICATE = 43;
SSL3_ALERT_TYPE_CERTIFICATE_REVOKED = 44;
SSL3_ALERT_TYPE_CERTIFICATE_EXPIRED = 45;
SSL3_ALERT_TYPE_CERTIFICATE_UNKNOWN = 46;
SSL3_ALERT_TYPE_ILLEGAL_PARAMETER = 47;
SSL3_ALERT_TYPE_UNKNOWN_CA = 48;
SSL3_ALERT_TYPE_ACCESS_DENIED = 49;
SSL3_ALERT_TYPE_DECODE_ERROR = 50;
SSL3_ALERT_TYPE_DECRYPT_ERROR = 51;
SSL3_ALERT_TYPE_EXPORT_RESTRICTION = 60;
SSL3_ALERT_TYPE_INAPPROPRIATE_FALLBACK = 86;
SSL3_ALERT_TYPE_PROTOCOL_VERSION = 70;
SSL3_ALERT_TYPE_INSUFFICIENT_SECURITY = 71;
SSL3_ALERT_TYPE_INTERNAL_ERROR = 80;
SSL3_ALERT_TYPE_USER_CANCELED = 90;
SSL3_ALERT_TYPE_NO_RENEGOTIATION = 100;
SSL3_ALERT_TYPE_UNSUPPORTED_EXTENSION = 110;
SSL3_ALERT_TYPE_CERTIFICATE_UNOBTAINABLE = 111;
SSL3_ALERT_TYPE_UNRECOGNIZED_NAME = 112;
SSL3_ALERT_TYPE_BAD_CERTIFICATE_STATUS_RESPONSE = 113;
SSL3_ALERT_TYPE_BAD_CERTIFICATE_HASH_VALUE = 114;

global_var
  SSL3_HANDSHAKE_TYPE_HELLO_REQUEST,
  SSL3_HANDSHAKE_TYPE_CLIENT_HELLO,
  SSL3_HANDSHAKE_TYPE_SERVER_HELLO,
  SSL3_HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST,
  SSL3_HANDSHAKE_TYPE_NEW_SESSION_TICKET,
  SSL3_HANDSHAKE_TYPE_CERTIFICATE,
  SSL3_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE,
  SSL3_HANDSHAKE_TYPE_CERTIFICATE_REQUEST,
  SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE,
  SSL3_HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
  SSL3_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
  SSL3_HANDSHAKE_TYPE_FINISHED,
  SSL3_HANDSHAKE_TYPE_CERTIFICATE_URL,
  SSL3_HANDSHAKE_TYPE_CERTIFICATE_STATUS,
  SSL3_HANDSHAKE_TYPE_SUPPLEMENTAL_DATA;

SSL3_HANDSHAKE_TYPE_HELLO_REQUEST = 0;
SSL3_HANDSHAKE_TYPE_CLIENT_HELLO = 1;
SSL3_HANDSHAKE_TYPE_SERVER_HELLO = 2;
SSL3_HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST = 3;
SSL3_HANDSHAKE_TYPE_NEW_SESSION_TICKET = 4;
SSL3_HANDSHAKE_TYPE_CERTIFICATE = 11;
SSL3_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12;
SSL3_HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13;
SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14;
SSL3_HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15;
SSL3_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16;
SSL3_HANDSHAKE_TYPE_FINISHED = 20;
SSL3_HANDSHAKE_TYPE_CERTIFICATE_URL = 21;
SSL3_HANDSHAKE_TYPE_CERTIFICATE_STATUS = 22;
SSL3_HANDSHAKE_TYPE_SUPPLEMENTAL_DATA = 23;

###
# The includes come after the global_var declarations to silence
# warnings.
###
include("starttls.inc");

#
#
# This function generates an SSL / TLS Client Hello message. For specs, see:
#   - http://www.mozilla.org/projects/security/pki/nss/ssl/draft02.html (SSL v2)
#   - http://www.mozilla.org/projects/security/pki/nss/ssl/draft302.txt (SSL v3)
#   - http://www.ietf.org/rfc/rfc2246.txt (TLS v1.0)
#
# Args:
#   o mlen = message length after this byte; 1 byte.
#   o mtype = handshake message type; 1 byte.
#     nb: 0x01 => Client Hello (default).
#   o version = client SSL version; 2 bytes.
#     nb: 0x0002 => SSLv2, 0x0300 => SSLv3 (default), 0x0301 => TLSv1.
#   o v2hello = whether to use v2 client hello format.
#     nb: FALSE (use protocol-specific format), TRUE (default).
#   o cipherspec = which ciphers are supported.
#   o cspeclen = cipher spec len; 2 bytes.
#   o sessionid = session ID (defaults to empty string
#     or random bytes if sessionidlen is non-zero).
#   o sessionidlen = session ID length; 2 bytes for SSLv2, 1 byte otherwise.
#   o challenge = random bytes of challenge data.
#     nb: for SSLv2, defaults to a random string.
#         for SSLv3 or TLSv1, defaults to current unix datetime
#         followed by a random string.
#   o challengelen = length of challenge; 2 bytes.
#     nb: this is used only with SSLv2 format hellos.
#   o compmeths = list of compression methods supported by client,
#     1 byte each (defaults to 0x00 => no compression).
#     nb: this is not used with SSLv2.
#   o compmethslen = length of compression methods.
#   o extensions = list of extensions
#     nb: this is used only with TLS (see RFC 4366)
#   o extensionslen = length of the list of extensions (optional)
#   o securerenegotiation = Advertise secure renegotiation in initial
#     handshake using empty ciphersuite method. SSLv3 and up.
# Return:
#   o a raw string representing the Client Hello message.
#
# updated: 16-Nov-2004, George A. Theall
#
# updated: 29-Dec-2004, Tenable Network Security / jwl
function client_hello(mlen, mtype, version, v2hello, cipherspec, cspeclen, sessionid, sessionidlen, challenge, challengelen, compmeths, compmethslen, extensions, extensionslen, securerenegotiation, maxver) {
  local_var chello, chellolen, handshake, myhello;

  # Assign some defaults.
  if ( (mtype <= 0) || isnull(version) ) mtype = raw_string(0x01);			# set to hello packet by default
  if (isnull(version)) version = raw_string(0x03, 0x00);
  if (isnull(v2hello)) v2hello = TRUE;
  if (isnull(securerenegotiation)) securerenegotiation = FALSE;

  # Generate the hello.
  #
  # - SSLv2, whether it's explicitly SSLv2 or in v2 compatibility mode.
  if (version == raw_string(0x00, 0x02) || v2hello == TRUE) {
    # Assign other defaults.
    #
    # - ciphers.
    if (isnull(cipherspec)) {
      if ( (isnull(cspeclen)) || (cspeclen <= 0 ) ) 
        cipherspec = 
          ciphers["SSL2_CK_RC2_128_CBC_EXPORT40_WITH_MD5"] +
          ciphers["SSL2_CK_RC4_128_EXPORT40_WITH_MD5"] +
          ciphers["SSL2_CK_RC4_128_WITH_MD5"] +
          ciphers["SSL2_CK_DES_192_EDE3_CBC_WITH_MD5"];
      else 
        # nb: fill it with random bytes.
        while (strlen(cipherspec) < cspeclen)
          cipherspec = cipherspec + (rand() % 256);
    }
    if (isnull(cspeclen)) {
      cspeclen = strlen(cipherspec); 
      cspeclen = raw_string(cspeclen / 256, cspeclen % 256);
    }
    # - session ID.
    if (isnull(sessionid)) {
      if (sessionidlen) 
        # nb: fill it with random bytes.
        while (strlen(sessionid) < sessionidlen)
          sessionid = sessionid + (rand() % 256);
      else sessionid = "";
    }
    if (isnull(sessionidlen)) {
      sessionidlen = strlen(sessionid);
      sessionidlen = raw_string(sessionidlen / 256, sessionidlen % 256);
    }
    # - challenge.
    if (isnull(challenge)) challenge = rand_str(length:16);
    if (isnull(challengelen)) {
      challengelen = strlen(challenge);
      challengelen = raw_string(challengelen / 256, challengelen % 256);
    }

    # Assemble the message.
    # nb: 2 byte length code is used since we don't need any padding.
    handshake = mtype +
                version +
                cspeclen +
                sessionidlen +
                challengelen +
                cipherspec;
    if (sessionid) handshake = handshake + sessionid;
    handshake = handshake + challenge;
    if ( (mlen <= 0) || isnull(mlen) ) mlen = strlen(handshake);
    myhello = raw_string(0x80 | (mlen / 256), mlen % 256) + handshake;
  }
  # - SSLv3 to TLSv12.
  else if (
    version == raw_string(0x03, 0x00) ||
    version == raw_string(0x03, 0x01) ||
    version == raw_string(0x03, 0x02) ||
    version == raw_string(0x03, 0x03)
  ) {
    # Assign other defaults.
    #
    # - ciphers.
    if (isnull(cipherspec)) {
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
    if (isnull(cspeclen)) {
      cspeclen = strlen(cipherspec);
      cspeclen = raw_string(cspeclen / 256, cspeclen % 256);
    }
    if (securerenegotiation)
    {
      # This value isn't actually a cipher, instead it signals to
      # the server that the client supports secure renegotiation.
      cipherspec += raw_string(0x00, 0xff);
      cspeclen = strlen(cipherspec);
      cspeclen = raw_string(cspeclen / 256, cspeclen % 256);
    }
    # - session ID.
    if (isnull(sessionid)) {
      if (sessionidlen) {
        # nb: fill out field with random bytes.
        while (strlen(sessionid) < sessionidlen)
          sessionid = sessionid + (rand() % 256);
      }
      else sessionid = "";
    }
    if (isnull(sessionidlen)) sessionidlen = raw_string(strlen(sessionid));
    # - challenge.
    if (isnull(challenge)) challenge = dec2hex(num:unixtime()) + rand_str(length:28);
    # - compression methods
    if (isnull(compmeths)) {
      compmeths = raw_string(0x00);
      # nb: fill out field with random bytes.
      while (strlen(compmeths) < compmethslen)
        compmeths = compmeths + (rand() % 256);
    }
    if (isnull(compmethslen)) compmethslen = raw_string(strlen(compmeths));

    # Assemble the message.
    if(isnull(maxver))
      maxver = version;
    chello = maxver +
             challenge + 
             sessionidlen + sessionid +
             cspeclen + cipherspec +
             compmethslen + compmeths;
    if (!isnull(extensions))
    {
      if (isnull(extensionslen))
        extensionslen = mkword(strlen(extensions));
      chello += extensionslen + extensions;
    }

    chellolen = strlen(chello);
    handshake = mtype +
              raw_string(0, chellolen / 256, chellolen % 256) +
              chello;
    if (isnull(mlen)) mlen = strlen(handshake);
    myhello = raw_string(0x16) +
              version +
              raw_string(mlen / 256, mlen % 256) +
              handshake;
  }

  return(myhello);
}

function client_send_cert (contenttype, version, length, hshaketype, hlength, clength, clength2, certificate) {
  # contenttype = content type (1 byte) -- handshake is 0x16
  # version = version (2 bytes) -- SSL v3 is 0x03 0x00
  # length = length (2 bytes) of record following this length field
  # hshaketype = handshake type (1 byte) -- certificate is 0x0B
  
  # Note to self:  3 bytes is a *lot* of space...

  # hlength = handshake length (3 bytes) (also equal to length - 4)
  # clength = certificate length (3 bytes) (or hlength - 3)
  # clength2 = actual cert length (3 bytes) (just subtract another 3 from clength)
  # certificate = clength2 bytes of certificate

  local_var certlen, client_cert, tlen;

  if (!certificate) exit(0);                      # must have a cert... 

  certlen = strlen(certificate);

  if (!contenttype) contenttype = raw_string(0x16);
  if (!version) version = raw_string(0x03, 0x00);
  if (!hshaketype) hshaketype = raw_string(0x0B);

  if (!clength2) {
    clength2 = certlen; 
    if (clength2 <= 0xFF) clength2 = raw_string(0x00, 0x00, clength2);
    else clength2 = raw_string(0x00, clength2 / 256, clength2 % 256); 
  }

  if (!clength) {
      tlen = certlen + 3;
      if (tlen <= 0xFF) clength = raw_string(0x00, 0x00, tlen);
      else clength = raw_string(0x00, tlen / 256, tlen % 256); 
  }

  if (!hlength) {
      tlen = certlen + 6;
      if (certlen <= 0xFF) hlength = raw_string(0x00, 0x00, tlen);
      else hlength = raw_string(0x00, tlen / 256, tlen % 256);
  }

  if (!length) {
    length = certlen + 10;
    if (length <= 0xFF) length = raw_string(0x00, strlen(length));
    else length = raw_string(length / 256, length % 256);
  }
    
  client_cert = contenttype + version + length + hshaketype + hlength + clength + clength2 + certificate;
  return (client_cert); 
}

# This function returns the message digest (fingerprint) of a string.
#
# Args:
#   o string - the string to fingerprint.
#   o type - the type of message digest to use, either 
#     MD2, MD5 (default), SHA1, SHA256
#
# Return:
#   o a string of hex numbers, each separated by a colon, representing 
#     the string's fingerprint.
#
# updated: 16-Nov-2004, George A. Theall
#
function fingerprint_string(str, type) {
  local_var digest;

  if (isnull(str)) return(NULL);
  if (isnull(type)) type = "md5";

  if (type =~ "md2") {
    digest = MD2(str);
  }
  else if (type =~ "md5") {
    digest = MD5(str);
  }
  else if (type =~ "sha1") {
    digest = SHA1(str);
  }
  else if (type =~ "sha256" && defined_func("SHA256")) {
    digest = SHA256(str);
  }
  else {
    # unsupported digest type.
    return(NULL);
  }

  digest = ereg_replace(string:hexstr(digest), pattern:"(..)", replace:"\1:");
  digest = substr(digest, 0, strlen(digest)-2);

  return(digest);
}

# This function returns the message digest (fingerprint) of an SSL 
# certificate.
#
# Args:
#   o cert - the certificate (either PEM or DER-encoded).
#   o type - the type of digest to use, either MD5 (default) or SHA1.
#
# Return:
#   o a string of hex numbers, each separated by a colon, representing 
#     the certificate's fingerprint.
function fingerprint_cert(cert, type) {
  local_var der, line;;

  if (isnull(type)) type = "md5";

  # If the cert is PEM-encoded, convert it to DER-encoding.
  if (egrep(string:cert, pattern:"(BEGIN CERTIFICATE|^.{64}$)")) {
    der = "";
    foreach line (split(cert, keep:TRUE)) {
      if (line !~ "^-+(BEGIN|END) CERTIFICATE-+$") {
        der += line;
      }
    }
    cert = base64_decode(str:der);
  }

  return(fingerprint_string(str:cert, type:type));
}

# This function returns the server certificate for the SSL-enabled
# service on a given port.
#
# Args:
#   o port - a port number.
#   o encoding - format of certificate, either PEM (default) or DER.
#   o socket - an already open socket (optional).
#   o encaps - the type of encapsulation to use (optional).
#   o sort - indicate whether the cert chain should be reordered.
#   o securerenegotiation - Advertise secure renegotiation in initial
#     handshake using empty ciphersuite method. SSLv3 and up.
#   o sni - Enable(default)/Disable TLS SNI extension. TLSv1.0/v1.1/v1.2
#
# Return:
#   o a string representing the SSL certificate.
function get_server_cert(port, encoding, socket, encaps, getchain, sort, securerenegotiation, sni)
{
  local_var buf, hello, done, hexmsg, host, soc, ssl;
  local_var extensions, servername;
  local_var msg, msg_len, msg_type;
  local_var hand, hand_len, hand_type;
  local_var cert, cert_len, cipherspec;
  local_var alert_desc, alert_lvl, err_code;
  local_var i, n;
  local_var idx;
  local_var kb, sni_kb, list;

  if (isnull(port)) return(NULL);
  if (isnull(encoding)) encoding = "pem";
  if (isnull(sort)) sort = TRUE;
  if (isnull(securerenegotiation)) securerenegotiation = FALSE;
  if (isnull(sni)) sni = TRUE;
  cert = make_list();
  n = 0;

  if (get_kb_item("SSL/NO_SNI/" + port))
  {
    sni = FALSE;
  }

  host = get_host_name();

  if (sni && host == get_host_ip())
  {
    sni = FALSE;
    replace_kb_item(name:"SSL/NO_SNI/" + port, value:TRUE);
    set_kb_item(name:"SSL/NO_SNI/" + port + "/reason", value:"hostname-is-ip-address");
  }

  if (sni)
  {
    sni_kb = "SNI/";
  }
  else
  {
    sni_kb = "";
  }

  # Try to get cert from the KB.
  cert[0] = get_kb_item("SSL/Certificate/" + sni_kb + port);
  if ( !isnull(cert[0]) )
  {
   for ( i = 1;  TRUE ; i ++ )
    {
     kb = get_kb_item("SSL/Certificate/" + sni_kb + port + "/" + i);
     if ( isnull(kb) ) break;
     cert[i] = kb;
    }
  }
  # If that didn't work, retrieve it directly.
  else {
    if (!get_port_state(port)) return(NULL);
    if (isnull(socket))
    {
      soc = open_sock_tcp(port, transport:ENCAPS_IP);
      if (!soc) return(NULL);
    }
    else soc = socket;

    if (isnull(encaps)) encaps = get_kb_item("Transports/TCP/"+port);

    if (isnull(encaps))
    {
      list = get_kb_list("SSL/Transport/"+port);
      if (list)
      {
        list = make_list(list); 
        if(max_index(list) > 0)
          encaps = list[0];
        else
          return (NULL);
      }
      else
        return (NULL);
    }

    # nb: see nessus-libraries/include/libnessus.h for defines
    #     mapping encapsulations to SSL / TLS version.
    if (encaps == ENCAPS_SSLv2) ssl = "SSLv2";
    else if (encaps == ENCAPS_SSLv3 || encaps == ENCAPS_SSLv23) ssl = "SSLv3";
    else if (encaps == ENCAPS_TLSv1) ssl = "TLSv1";
    else if (encaps == COMPAT_ENCAPS_TLSv11) ssl = "TLSv11";
    else if (encaps == COMPAT_ENCAPS_TLSv12) ssl = "TLSv12";
    else return(NULL);

    if (sni && (ssl == "SSLv2" || ssl == "SSLv3"))
    {
      sni = FALSE;
      replace_kb_item(name:"SSL/NO_SNI/" + port, value:TRUE);
      set_kb_item(name:"SSL/NO_SNI/" + port + "/reason", value:"sslv3-or-v3");
    }

    # We specify some ECDHE ciphers (if TLS1.0 or higher), so we need ECC
    # extensions. See RFC 4492.
    # It is a SHOULD (not MUST) that clients send ec_point_formats, but rumor
    # has it older PolarSSL would terminate connections without it.
    # All implementations MUST support "uncompressed".
    extensions = '\x00\x0b' + # extension: ec_point_formats
                 '\x00\x02' + # length of opaque extensionData (all following bytes)
                 '\x01' +     # First field in ECPointFormatList: length (in bytes) of the following list of identifiers
                 '\x00';      # "uncompressed" point format

    extensions += '\x00\x0a' + # extension: elliptic_curves
                  '\x00\x14' + # length of opaque extensionData (all following bytes)
                  '\x00\x12' + # First field in EllipticCurveList: length (in bytes) of the following list of identifiers
                  # RFC says ordering is "by client preference". Choices and ordering inspired by Chrome and Firefox.
                  elliptic_curves["CURVE_SECP521R1"] +
                  elliptic_curves["CURVE_SECP384R1"] +
                  elliptic_curves["CURVE_SECP256R1"] +
                  elliptic_curves["CURVE_SECT571R1"] +
                  elliptic_curves["CURVE_SECT571K1"] +
                  elliptic_curves["CURVE_SECT409R1"] +
                  elliptic_curves["CURVE_SECT409K1"] +
                  elliptic_curves["CURVE_SECT283R1"] +
                  elliptic_curves["CURVE_SECT283K1"];

    if (sni) {
      # RFC 6066
      # 00XXXX[host string]
      # 00 specifies host_name type
      # XXXX is length of host string
      servername = mkbyte(0) + mkword(strlen(host)) + host;
      # 0000XXXXYYYY[servername string]
      # 0000 specifies server_name (SNI) extension type
      # XXXX is the total length (length of YYYY and servername string)
      # YYYY is the length of the servername list (servername string)
      extensions += mkword(0) +
                    mkword(strlen(servername) + 2) +
                    mkword(strlen(servername)) +
                    servername;
    }

    # This is the list of ciphers from `openssl ciphers DEFAULT`.
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

    # Send client hello.
    if (ssl == 'SSLv2') {
      hello = client_hello(version:raw_string(0x00, 0x02));
    }
    else if (ssl == 'SSLv3') {
      hello = client_hello(v2hello:FALSE, version:raw_string(0x03, 0x00), securerenegotiation:securerenegotiation);
    }
    else {
      cipherspec +=
        # GCM ciphersuites are only available in TLS 1.2
        ciphers["TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256"] +
        ciphers["TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384"] +
        # These are also only available in TLS 1.2, but allow compat if GCM is disabled.
        ciphers["TLS1_ECDHE_RSA_WITH_AES_128_CBC_SHA256"] +
        ciphers["TLS1_ECDHE_RSA_WITH_AES_256_CBC_SHA384"] +
        # These two are for ECDHE in TLS 1.0: `openssl ciphers TLSv1+EECDH+aRSA+AES`
        ciphers["TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA"] +
        ciphers["TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA"];

      if (ssl == 'TLSv1') {
        hello = client_hello(v2hello:FALSE, version:raw_string(0x03, 0x01), securerenegotiation:securerenegotiation, extensions:extensions, cipherspec:cipherspec);
      }
      else if (ssl == 'TLSv11') {
        hello = client_hello(v2hello:FALSE, version:raw_string(0x03, 0x02), extensions:extensions, cipherspec:cipherspec);
      }
      else if (ssl == 'TLSv12') {
        hello = client_hello(v2hello:FALSE, version:raw_string(0x03, 0x03), extensions:extensions, cipherspec:cipherspec);
      }
    }
    send(socket:soc, data:hello);
    buf = recv(socket:soc, length:16384);
    if (isnull(socket)) close(soc);

    # Process server message(s). 
    done = 0;
    if (ssl == 'SSLv2') {
      # Isolate a message.
      while (!done && strlen(buf) > 3) {
        msg_type = ord(buf[2]);
        msg_len = ((ord(buf[0]) & 0x7f) << 8) | ord(buf[1]);
        msg = substr(buf, 0, msg_len+2-1);
        buf = substr(buf, msg_len);

        # Handshake message.
        if (msg_type == 4 && strlen(msg) > 14) {
          # X.509 certificate.
          if (ord(msg[4]) == 1) {
            cert_len = ord(msg[7])*256 + ord(msg[8]);
            cert[0] = substr(msg, 13, cert_len+13-1);
            done = 1;
          }
        }
        # Error message.
        else if (msg_type == 0 && strlen(msg) == 2) {
          err_code = ord(msg[0]) * 256 + ord(msg[1]);
        }
        # Something else.
        else {
          if (debug_level > 1) display("Message of type ", msg_type, " received from ", host, ":", port, "!\n");
        }
      }
    }
    else if (ssl == 'SSLv3' || ssl == 'TLSv1' || ssl == 'TLSv11' || ssl == 'TLSv12') {
      # We *should* see the Server Hello handshake first, followed by the Server
      # Certificate handshake, but not depending on the order is more robust.
      while (!done && strlen(buf) > 5) {
        msg_type = ord(buf[0]);
        msg_len = ord(buf[3])*256 + ord(buf[4]);
        # nb: msg_len doesn't include the first 5 bytes.
        msg = substr(buf, 0, msg_len+5-1);
        buf = substr(buf, msg_len+5);

        # Handshake message.
        if (msg_type == 22 && strlen(msg) > 3) {
          while (!done && strlen(msg) > 8) {
            hand_type = ord(msg[5]);
            hand_len = ord(msg[6])*65536 + ord(msg[7])*256 + ord(msg[8]);
            # nb: hand_len doesn't include the first 4 bytes.
            hand = substr(msg, 5, hand_len+4+5-1);

            # Certificate handshake.
            if (hand_type == 11 && strlen(hand) > 7) {
	      idx = 7;
	      n = 0;
              while ( idx < strlen(hand) )
              {
               # First cert belongs to the server itself.
 	       if ( idx + 3 > strlen(hand) ) break;
               cert_len = ord(hand[idx])*65536 + ord(hand[idx+1])*256 + ord(hand[idx+2]);
               cert[n++] = substr(hand, idx+3, cert_len+idx+3-1);
               idx += cert_len + 3;
              }
              done = 1;
            }
            msg = substr(msg, hand_len+4);
          }
        }
        # Alert message.
        else if (msg_type == 21 && strlen(msg) == 7) {
          alert_lvl = ord(msg[5]);
          alert_desc = ord(msg[6]);
          # SNI is enabled and fatal alert and unrecognized_name
          if (sni && alert_lvl == SSL3_ALERT_TYPE_FATAL && alert_desc == SSL3_ALERT_TYPE_UNRECOGNIZED_NAME) {
            # Try again without SNI
            replace_kb_item(name:"SSL/NO_SNI/" + port, value:TRUE);
            set_kb_item(name:"SSL/NO_SNI/" + port + "/reason", value:"name(" + host + ") returned fatal unrecognized-name");
            return get_server_cert(port:port, encoding:encoding, socket:socket, encaps:encaps, getchain:getchain, sort:sort, securerenegotiation:securerenegotiation, sni:FALSE);
          }
        }
        # Something else.
        else {
          if (debug_level > 1) display("Non-handshake message of type ", msg_type, " received from ", host, ":", port, "!\n");
        }
      }
    }

    if (done) {
      for ( i = 0 ; i < max_index(cert); i ++ )
      {
        cert[i] = blob_to_pem(cert[i]);

        if ( i == 0 ) replace_kb_item(name:"SSL/Certificate/" + sni_kb + port, value:cert[i]);
        else replace_kb_item(name:"SSL/Certificate/" + sni_kb + port + "/" + i, value:cert[i]);
      }
    }
    else {
      # The port was open but we couldn't get the certificate for some reason
      # so let the user know if we're verbosely logging.
      if (debug_level > 1) display("Can't get SSL certificate on ", host, ":", port, "!\n");
      return(NULL);
    }
  }

  if (encoding =~ "der") {
    local_var der, line;
    for ( i = 0 ; i < max_index(cert) ; i ++ )
    {
      cert[i] = pem_to_blob(cert[i]);
    }
  }
  else if (encoding !~ "pem") {
    # unsupported encoding.
    return(NULL);
  }

  if ( sort ) cert = sort_cert_chain(cert);

  if ( getchain == TRUE ) 
  {
   if ( max_index(cert) == 0 ) return NULL;
   return cert;
  }
  else return cert[0];
}

function recv_ssl(socket, partial, timeout)
{
  local_var b1, b2, l, r1, r2;

  r1 = recv(socket:socket, length:5, min:5, timeout:timeout);
  if (strlen(r1) != 5) return NULL;

  b1 = ord(r1[1]);
  b2 = ord(r1[2]);
  if (b1 == 3 && b2 >= 0 && b2 <= 3)                        # SSL3 to TLS1.2
    l = ord(r1[3])*256 + ord(r1[4]);
  else                                                      # SSL2
  {
    # 2-byte record header
    if(ord(r1[0]) & 0x80)
    {
      l = ((ord(r1[0]) & 0x7f) << 8) | ord(r1[1]);
      l -= 3;
    }
    # 3-byte record header
    else
    {
      l = ((ord(r1[0]) & 0x3f) << 8) | ord(r1[1]); 
      l -= 2; # account for 1-byte padlen
    }
  }
  if (l > 0)
  {
    r2 = recv(socket:socket, length:l, min:l, timeout:timeout);
    if (partial || strlen(r2) == l) return r1+r2;
  }

  return NULL;
}

function load_CA()
{
 local_var data, data_custom;
 local_var ret;
 local_var raw;
 local_var r;
 local_var line;
 local_var der;
 local_var inCert;
 local_var n;

 local_var ca_list, ca_file;


 ret = raw = make_list();
 if ( defined_func("get_global_var") )
 {
  mutex_lock("ssl_func.inc:load_CA");
  ret = get_global_var("CA");
  if ( ! isnull(ret) )
  {
   mutex_unlock("ssl_func.inc:load_CA");
   return ret;
  }
 }

 ca_list = get_kb_list("SSL/CA_list");
 data = '';
 data_custom = '';
 foreach ca_file (ca_list)
 {
  if('custom_CA' ><  ca_file)
  {
    if (file_stat(ca_file) > 0) data_custom += fread(ca_file);
  }
  else
  {
    if (file_stat(ca_file) > 0) data += fread(ca_file);
  }
 }
 if ( (strlen(data) + strlen(data_custom)) <= 0) return NULL;

 inCert = FALSE;
 n = 0;

  foreach line (split(data, keep:FALSE)) {
      if ( line =~ "^-+BEGIN CERTIFICATE-+$" )
      {
	inCert = TRUE;
        der = NULL; 
      }
      else if (line =~ "^-+END CERTIFICATE-+$") 
      {
    	raw[n] = base64_decode(str:der);
    	ret[n] = parse_der_cert(cert:raw[n]);
	n++;
	der = NULL;
	inCert = FALSE;
      }
      else if ( inCert ) der += line;
    }

 inCert = FALSE;

  foreach line (split(data_custom, keep:FALSE)) {
      if ( line =~ "^-+BEGIN CERTIFICATE-+$" )
      {
	inCert = TRUE;
        der = NULL; 
      }
      else if (line =~ "^-+END CERTIFICATE-+$") 
      {
    	raw[n] = base64_decode(str:der);
    	ret[n] = parse_der_cert(cert:raw[n], customCA:TRUE);
	n++;
	der = NULL;
	inCert = FALSE;
      }
      else if ( inCert ) der += line;
    }

  r[0] = ret;
  r[1] = raw;
 if ( defined_func("get_global_var") )
 {
  if ( !isnull(r) ) set_global_var(name:"CA", value:r);
  mutex_unlock("ssl_func.inc:load_CA");
 }

  return r;
}

##
# Encode variable-length data for inclusion in SSL records.
#
# @param data The data to be stored in the record.
# @param len The number of bytes required to store the maximum length
#            of the data for the record's field, two by default.
#
# @remark Works for SSL version 3.0 and later, but probably not for
#         version 2.0.
#
# @remark Can only handle fields up to 4 bytes, currently. Since NASL
#         has no unsigned types, [strlen] can't return a full 4 byte
#         length.
#
# @return The data prepended with the length.
##
function ssl_vldata_put(data, len)
{
  local_var dlen, i, n;

  # Sanity check parameters.
  if (isnull(len))
    return NULL;
  if (len > 4)
    return NULL;

  # Get the length of the data.
  dlen = strlen(data);
  if (
    (len == 1 && dlen > 0x000000FF) ||
    (len == 2 && dlen > 0x0000FFFF) ||
    (len == 3 && dlen > 0x00FFFFFF)
  ) return NULL;

  # Encode the data length, padded as necessary.
  n = "";
  for (i = len - 1; i >= 0; i--)
    n += mkbyte((dlen >> (i * 8)) & 0xff);

  return n + data;
}

##
# Extract variable-length data from SSL records.
#
# @param blob Data blob in which the data resides.
# @param len The number of bytes required to store the maximum length
#            of the data for the record's field, two by default.
# @param pos Position where the data starts, zero by default.
#
# @remark Works for SSL version 3.0 and later, but probably not for
#         version 2.0.
#
# @remark Can only handle fields up to 4 bytes, currently. Since NASL
#         has no unsigned types, [strlen] can't return a full 4 byte
#         length.
#
# @return An array containing the data and number of bytes consumed.
##
function ssl_vldata_get(blob, len, pos)
{
  local_var i, n;

  # Sanity check parameters.
  if (isnull(blob) || isnull(len))
    return NULL;
  if (len > 4)
    return NULL;

  # Set defaults.
  if (isnull(len))
    len = 2;
  if (isnull(pos))
    pos = 0;

  # prevent errors in nessusd.dump for out of range index
  if((len + pos) > strlen(blob))
    return NULL;

  # Extract the data length.
  n = 0;
  for (i = len - 1; i >= 0; i--)
    n += ord(blob[pos++]) << (i * 8);

  # Check that the length won't run past the end of the blob.
  if (pos + n > strlen(blob))
    return NULL;

  return make_array(
    "data", substr(blob, pos, pos + n - 1),
    "len", len + n
  );
}

##
# Parses the SSL record at a given offset.
#
# In the case of SSLv3/TLSv1, multiple higher-level elements can be
# put inside of a single record. The element parameter exists to allow
# the caller to specify which of these higher-level elements they want
# parsed.
#
# SSLv3/TLSv1 also permit a single higher-level element to span
# multiple records. That isn't supported by this function.
#
# @param blob A stream of records
# @param element Index of an element inside a record
# @param encrypted Boolean indicated whether the record is encrypted,
#                  false by default
# @param offset Byte offset at which to begin parsing
#
# @return NULL on error, integer on end of record, and an array
#         representing the parsed record on success
##
function ssl_parse(blob, element, encrypted, offset)
{
  local_var end, i, id, len, length, num, rec, subend, ver;

  # Sanity check arguments.
  if ( isnull(blob) ) return NULL;
  if ( isnull(offset) ) offset = 0;
  if ( strlen(blob) - offset < 5 ) return NULL;
  if ( isnull(element) ) element = 0;
  if ( isnull(encrypted) ) encrypted = FALSE;

  # Initialize record.
  rec = make_array();
  rec["start_offset"] = offset;

  ver = getword(blob:blob, pos:offset + 1);
  if ( ver >= 0x0300 && ver <= 0x0303 )
  {
    # Parse SSLv3 and TLSv1 header.
    rec["content_type"] = getbyte(blob:blob, pos:offset);
    offset += 1;
    rec["version"] = ver;
    offset += 2;
    rec["length"] = getword(blob:blob, pos:offset);
    offset += 2;

    # Set end offset based on declared length.
    rec["end_offset"] = rec["start_offset"] + 5 + rec["length"];
    if ( rec["end_offset"] > strlen(blob) ) return NULL;

    # If the record is encrypted, we can't look any further than this.
    # Consider the rest of the record as a blob.
    if ( encrypted )
    {
      # We can't look inside, so we can't check for higher-level
      # elements.
      if (element != 0) return rec["end_offset"];

      rec["data"] = substr(blob, offset, offset + rec["end_offset"] - 1);
      return rec;
    }

    # A single SSL record may contain several higher-level elements.
    # We need to find the element specified by the caller.
    for ( i = 0; i < element; i++ )
    {
      # Check if there's more higher-level elements.
      if ( offset + 4 >= rec["end_offset"] ) return rec["end_offset"];

      # Only handshake elements tend to be concatenated.
      if ( rec["content_type"] != SSL3_CONTENT_TYPE_HANDSHAKE ) return rec["end_offset"];

      # Skip this element's type, length, and body.
      offset += 1;
      length = (ord(blob[offset]) << 16) | (ord(blob[offset + 1]) << 8) | ord(blob[offset + 2]);
      offset += 3;
      offset += length;
    }
    rec["element"] = i;
    if ( offset >= rec["end_offset"] ) return rec["end_offset"];

    if ( rec["content_type"] == SSL3_CONTENT_TYPE_HANDSHAKE )
    {
      # Parse handshake header.
      if ( offset + 4 > rec["end_offset"] ) return NULL;
      rec["handshake_type"] = getbyte(blob:blob, pos:offset);
      offset += 1;
      rec["handshake_length"] = (ord(blob[offset]) << 16) | (ord(blob[offset + 1]) << 8) | ord(blob[offset + 2]);
      offset += 3;

      # Handshake messages may end before the packet, since multiple
      # messages are often concatenated.
      rec["end_offset"] = offset + rec["handshake_length"];
      if ( rec["end_offset"] > strlen(blob) ) return NULL;

      if ( rec["handshake_type"] == SSL3_HANDSHAKE_TYPE_SERVER_HELLO )
      {
        if ( offset + 38 > rec["end_offset"] ) return NULL;
        rec["handshake_version"] = getword(blob:blob, pos:offset);
        offset += 2;
        rec["time"] = getdword(blob:blob, pos:offset);
        offset += 4;
        rec["random"] = substr(blob, offset, offset + 28 - 1);
        offset += 28;
        rec["session_id_length"] = getbyte(blob:blob, pos:offset);
        offset += 1;
        rec["session_id"] = substr(blob, offset, offset + rec["session_id_length"] - 1);
        offset += rec["session_id_length"];
        rec["cipher_spec"] = getword(blob:blob, pos:offset);
        offset += 2;
        rec["compression_method"] = getbyte(blob:blob, pos:offset);
        offset += 1;

        # A record without extensions might not have an extensions
        # length field.
        if ( offset < rec["end_offset"] )
        {
          if ( offset + 2 > rec["end_offset"] ) return NULL;
          rec["extensions_length"] = getword(blob:blob, pos:offset);
          offset += 2;

          # Calculate the end of all extensions.
          end = offset + rec["extensions_length"];
          if ( end > rec["end_offset"] ) return NULL;

          while ( offset < end )
          {
            # Parse out elements common to every extension.
            if ( offset + 4 > rec["end_offset"] ) return NULL;
            id = getword(blob:blob, pos:offset);
            offset += 2;
            length = getword(blob:blob, pos:offset);
            offset += 2;

            # Calculate the end of this extension.
            subend = offset + length;
            if ( subend > end ) return NULL;

            # Parse extension-specific fields.
            if ( id == 0xff01 )
            {
              if ( offset + 1 > subend ) return NULL;
              rec["extension_renegotiation_info_renegotiated_connection"] = getbyte(blob:blob, pos:offset);
              offset += 1;
            }
            else if ( id == 0xf)
            {
              if ( offset + 1 > subend ) return NULL;
              rec["extension_heartbeat_mode"] = getbyte(blob:blob, pos:offset);
              offset += 1;
            }
            else if ( id == 0x10)
            {
              # alpn length
              length = getword(pos:offset, blob:blob);
              offset += 2;
              # string length
              len = getbyte(pos:offset, blob:blob);
              offset += 1;
              rec['extension_alpn_protocol'] = substr(blob, offset, offset + len - 1);
              offset += (length - 1);
            }
            else if ( id == 0x3374 )
            {
              rec["extension_next_protocol_negotiation"] = make_list();

              # Parse out a limited number of protocols.
              for ( num = 0; num < 64 && offset < subend; num++ )
              {
                if ( offset + 1 > subend ) return NULL;
                len = getbyte(blob:blob, pos:offset);
                offset += 1;

                if ( offset + len > subend ) return NULL;
                rec["extension_next_protocol_negotiation"] = make_list(
                  rec["extension_next_protocol_negotiation"],
                  substr(blob, offset, offset + len - 1)
                );
                offset += len;
              }

              # Force the offset, in case we bailed out of the loop early.
              offset = subend;
            }
            # TLS Session Ticket extension
            else if ( id == 0x0023 )
            {
              # For ServerHello, this should always be zero bytes per
              # RFC 5077. Its presence just indicates that the actual
              # session ticket will be coming in the NewSessionTicket
              # handshake message.
              # Possibly there is a few bytes in here (an older,
              # deprecated RFC 4507 says so) so instead of presenting
              # the actual bytes, we just say whether the extension
              # is present or not.
              rec['extension_session_ticket'] = TRUE;
              offset += length;
            }
            else
            {
              offset += length;
            }
          }
        }
        else
        {
          rec["extensions_length"] = 0;
        }
      }
      else if ( rec["handshake_type"] == SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE )
      {
        # This handshake type contains no fields.
      }
      else if ( rec["handshake_type"] == SSL3_HANDSHAKE_TYPE_CLIENT_HELLO )
      {
        if ( offset + 35 > rec["end_offset"] ) return NULL;
        rec["handshake_version"] = getword(blob:blob, pos:offset);
        offset += 2;
        rec["time"] = getdword(blob:blob, pos:offset);
        offset += 4;
        rec["random"] = substr(blob, offset, offset + 28 - 1);
        offset += 28;
        rec["session_id_length"] = getbyte(blob:blob, pos:offset);
        offset += 1;
        if ( offset + rec["session_id_length"] > rec["end_offset"] ) return NULL;
        rec["session_id"] = substr(blob, offset, offset + rec["session_id_length"] - 1);
        offset += rec["session_id_length"];
        if ( offset + 2 > rec["end_offset"] ) return NULL;
        rec["cipher_specs_length"] = getword(blob:blob, pos:offset);
        offset += 2;

        end = offset + rec["cipher_specs_length"];
        if ( end > rec["end_offset"] ) return NULL;
        rec["cipher_specs"] = make_list();
        while ( offset < end )
        {
          rec["cipher_specs"] = make_list(
            rec["cipher_specs"],
            getword(blob:blob, pos:offset)
          );
          offset += 2;
        }

        if ( offset + 1 > rec["end_offset"] ) return NULL;
        rec["compression_methods_length"] = getbyte(blob:blob, pos:offset);
        offset += 1;

        end = offset + rec["compression_methods_length"];
        if ( end > rec["end_offset"] ) return NULL;
        rec["compression_methods"] = make_list();
        while ( offset < end )
        {
          rec["compression_methods"] = make_list(
            rec["compression_methods"],
            getbyte(blob:blob, pos:offset)
          );
          offset += 1;
        }
      }
      else if ( rec["handshake_type"] == SSL3_HANDSHAKE_TYPE_NEW_SESSION_TICKET )
      {
        if ( offset + 4 > rec["end_offset"] ) return NULL;
        # 32-bit unsigned seconds: how long to keep the ticket
        rec["ticket_lifetime_hint"] = getdword(substr(blob, offset, offset + 4));
        offset += 4;

        # Length field for the ticket
        if ( offset + 2 > rec["end_offset"] ) return NULL;
        rec["ticket_length"] = getword(substr(blob, offset, offset + 2));
        offset += 2;

        # The ticket is an opaque byte buffer
        if ( offset + rec["ticket_length"] > rec["end_offset"] ) return NULL;
        rec["ticket"] = substr(blob, offset, offset + rec["ticket_length"] - 1);
        offset += rec["ticket_length"];
      }
      else if ( rec["handshake_type"] == SSL3_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE )
      {
        if ( offset + rec["handshake_length"] > rec["end_offset"] ) return NULL;
        rec["data"] = substr(blob, offset, offset + rec["handshake_length"] - 1);
      }
      else if ( rec["handshake_type"] == SSL3_HANDSHAKE_TYPE_CERTIFICATE )
      {
        if ( offset + 3 > rec["end_offset"] ) return NULL;
        rec["certificates_length"] = (ord(blob[offset]) << 16) | (ord(blob[offset + 1]) << 8) | ord(blob[offset + 2]);
        offset += 3;

        end = offset + rec["certificates_length"];
        if ( end > rec["end_offset"] ) return NULL;
        rec["certificates"] = make_list();
        while ( offset < end )
        {
          if ( offset + 3 > rec["end_offset"] ) return NULL;
          length = (ord(blob[offset]) << 16) | (ord(blob[offset + 1]) << 8) | ord(blob[offset + 2]);
          offset += 3;

          if ( offset + length > rec["end_offset"] ) return NULL;
          rec["certificates"] = make_list(
            rec["certificates"],
            substr(blob, offset, offset + length - 1)
          );
          offset += length;
        }
      }
      else if ( rec["handshake_type"] == SSL3_HANDSHAKE_TYPE_CERTIFICATE_REQUEST )
      {
        if ( offset + rec["handshake_length"] > rec["end_offset"] ) return NULL;
        rec["data"] = substr(blob, offset, offset + rec["handshake_length"] - 1);
      }
      else
      {
        if ( offset + rec["handshake_length"] > rec["end_offset"] ) return NULL;
        rec["data"] = substr(blob, offset, offset + rec["handshake_length"] - 1);
      }
    }
    else if ( rec["content_type"] == SSL3_CONTENT_TYPE_APPLICATION_DATA )
    {
      rec["data"] = substr(blob, offset, rec["end_offset"] - 1);
    }
    else if ( rec["content_type"] == SSL3_CONTENT_TYPE_ALERT )
    {
      if ( offset + 2 > rec["end_offset"] ) return NULL;
      rec["level"] = getbyte(blob:blob, pos:offset);
      offset += 1;
      rec["description"] = getbyte(blob:blob, pos:offset);
      offset += 1;
    }
  }
  else
  {
    # Parse SSLv2.
    # 2-byte record header
    if(ord(blob[offset]) & 0x80)
    {
      rec["length"] = ((ord(blob[offset]) & 0x7f) << 8) | ord(blob[offset + 1]);
      offset += 2;
    }
    # 3-byte record header
    else
    {
      rec["length"] = ((ord(blob[offset]) & 0x3f) << 8) | ord(blob[offset + 1]);
      offset += 3;
    }

    # Set end offset based on declared length.
    rec["end_offset"] = rec["start_offset"] + 2 + rec["length"];
    if ( rec["end_offset"] > strlen(blob) ) return NULL;

    # Set the element to zero, since there can only ever be one
    # higher-level record in SSLv2.
    if ( element > 0) return rec["end_offset"];
    rec["element"] = 0;

    if ( offset + 1 > rec["end_offset"] ) return NULL;
    rec["content_type"] = getbyte(blob:blob, pos:offset);
    offset += 1;

    if ( rec["content_type"] == SSL2_CONTENT_TYPE_SERVER_HELLO )
    {
      if ( offset + 10 > rec["end_offset"] ) return NULL;
      rec["session_id_hit"] = getbyte(blob:blob, pos:offset);
      offset += 1;
      rec["certificate_type"] = getbyte(blob:blob, pos:offset);
      offset += 1;
      rec["version"] = getword(blob:blob, pos:offset);
      offset += 2;
      rec["certificate_length"] = getword(blob:blob, pos:offset);
      offset += 2;
      rec["cipher_specs_length"] = getword(blob:blob, pos:offset);
      offset += 2;
      rec["conn_id_length"] = getword(blob:blob, pos:offset);
      offset += 2;
      if ( offset + rec["certificate_length"] > rec["end_offset"] ) return NULL;
      rec["certificate"] = substr(blob, offset, offset + rec["certificate_length"] - 1);
      offset += rec["certificate_length"];

      end = offset + rec["cipher_specs_length"];
      if ( end > rec["end_offset"] ) return NULL;
      rec["cipher_specs"] = make_list();
      while ( offset < end )
      {
        rec["cipher_specs"] = make_list(
          rec["cipher_specs"],
          (ord(blob[offset]) << 16) | (ord(blob[offset + 1]) << 8) | ord(blob[offset + 2])
        );
        offset += 3;
      }

      if ( offset + rec["conn_id_length"] > rec["end_offset"] ) return NULL;
      rec["conn_id"] = substr(blob, offset, offset + rec["conn_id_length"] - 1);
      offset += rec["conn_id_length"];
    }
  }

  return rec;
}

##
# Parses the ServerKeyExchange record.
#
# @param blob Body of the ServerKeyExchange record.
# @param cipher Description of cipher suite.
# @param version SSL version.
#
# @remark [ssl_parse] cannot parse the contents of the ServerKeyExchange record
#         since you need information from previous records in the connection to
#         know its format.
#
# @return The encryption parameters.
##
function ssl_parse_srv_kex(blob, cipher, version)
{
  local_var curve_type, kex, pos, res;

  # Sanity check parameters.
  if (isnull(blob) || isnull(cipher))
    return NULL;

  kex = make_array();

  pos = 0;
  # Determine how the key should be parsed.
  if (cipher =~ "Kx=DH")
  {
    kex["kex"] = "dh";

    # Prime modulus
    res = ssl_vldata_get(blob:blob, pos:pos, len:2);
    if (isnull(res)) return NULL;
    kex['dh_p'] = res["data"];
    pos += res["len"];

    # Generator 
    res = ssl_vldata_get(blob:blob, pos:pos, len:2);
    if (isnull(res)) return NULL;
    kex['dh_g'] = res["data"];
    pos += res["len"];
     
    # The server's DH public value (g^X mod p)
    res = ssl_vldata_get(blob:blob, pos:pos, len:2);
    if (isnull(res)) return NULL;
    kex['dh_y'] = res["data"];
    pos += res["len"];

  }
  else if (cipher =~ "Kx=RSA")
  {
    kex["kex"] = "rsa";

    # Modulus
    res = ssl_vldata_get(blob:blob, pos:pos, len:2);
    if (isnull(res)) return NULL;
    kex['rsa_n'] = res["data"];
    pos += res["len"];
    
    # Public exponent 
    res = ssl_vldata_get(blob:blob, pos:pos, len:2);
    if (isnull(res)) return NULL;
    kex['rsa_e'] = res["data"];
    pos += res["len"];

  }
  # RFC 4492, section 5.4 
  else if (cipher =~ "Kx=ECDH")
  {
    kex["kex"] = "ecdh";
    curve_type = ord(blob[pos]); pos += 1;
  
    kex['curve_type'] = curve_type; 
    # NamedCurve
    if(curve_type == 3)
    {
      if(pos + 2 > strlen(blob)) return NULL;
      kex['named_curve'] = (ord(blob[pos]) << 8 ) + ord(blob[pos + 1]);
      pos += 2;
    } 
    # explicit_prime or explicit_char2
    else if (curve_type == 1 || curve_type == 2)
    {
      # explicit_prime 
      if(curve_type == 1)
      { 
        # prime
        res = ssl_vldata_get(blob:blob, pos:pos, len:1);
        if (isnull(res)) return NULL;
        kex['prime'] = res["data"];
        pos += res["len"];
      }
      # explicit_char2
      else
      {
        if(pos + 3 > strlen(blob)) return NULL;
        kex['m'] = (ord(blob[pos]) << 8 ) + ord(blob[pos + 1]);
        pos += 2;
    
        kex['basis'] = ord(blob[pos]); pos += 1;
       
        # ec_basis_trinomial or ec_basis_pentanomial
        if(kex['basis'] == 1 || kex['basis'] == 2)
        {
          # k1 
          res = ssl_vldata_get(blob:blob, pos:pos, len:1);
          if (isnull(res)) return NULL;
          kex['k1'] = res["data"];
          pos += res["len"];
   
          # ec_basis_pentanomial
          if(kex['basis'] == 2)
          {
            # k2
            res = ssl_vldata_get(blob:blob, pos:pos, len:1);
            if (isnull(res)) return NULL;
            kex['k2'] = res["data"];
            pos += res["len"];
        
            # k3
            res = ssl_vldata_get(blob:blob, pos:pos, len:1);
            if (isnull(res)) return NULL;
            kex['k3'] = res["data"];
            pos += res["len"];
          }
        }
        else return NULL;
      }

      # coefficient a of the curve 
      res = ssl_vldata_get(blob:blob, pos:pos, len:1);
      if (isnull(res)) return NULL;
      kex['curve_a'] = res["data"];
      pos += res["len"];
       
      # coefficient b of the curve 
      res = ssl_vldata_get(blob:blob, pos:pos, len:1);
      if (isnull(res)) return NULL;
      kex['curve_b'] = res["data"];
      pos += res["len"];

      # base 
      res = ssl_vldata_get(blob:blob, pos:pos, len:1);
      if (isnull(res)) return NULL;
      kex['base'] = res["data"];
      pos += res["len"];
      
      # order 
      res = ssl_vldata_get(blob:blob, pos:pos, len:1);
      if (isnull(res)) return NULL;
      kex['order'] = res["data"];
      pos += res["len"];
      
      # cofactor 
      res = ssl_vldata_get(blob:blob, pos:pos, len:1);
      if (isnull(res)) return NULL;
      kex['cofactor'] = res["data"];
      pos += res["len"];
    }
    # Unknown curve type
    else return NULL;
   
    # Public key in ECPOINT fmt 
    res = ssl_vldata_get(blob:blob, pos:pos, len:1);
    if (isnull(res)) return NULL;
    kex['pubkey'] = res["data"];
    pos += res["len"];
    
  }
  # Currently not support
  else
  {
    return NULL;
  }


  # Parse the signature.
  # tls 1.0 and 1.1:
  #   A digitally-signed element is encoded as an opaque 
  #   vector <0..2^16-1>,   
  # 
  # tls 1.2:
  #   A digitally-signed element is encoded as a struct DigitallySigned:
  # 
  #   struct {
  #       SignatureAndHashAlgorithm algorithm;
  #       opaque signature<0..2^16-1>;
  #    } DigitallySigned
  if(version == TLS_12)
  {
    if(pos + 2 > strlen(blob))
      return NULL;    

    kex["hash_alg"] = ord(blob[pos]);
    kex["sig_alg"]  = ord(blob[pos + 1]);
    pos += 2;
  }

  res = ssl_vldata_get(blob:blob, pos:pos, len:2);
  if (isnull(res))
    return NULL;
  kex["sig"] = res["data"];

  return kex;
}

##
# Tries to find an SSL record matching a specific set of criteria.
#
# This function accepts pairs of anonymous arguments that specify the
# values expected in certain fields, and returns the first record that
# matches all expectations.
#
# If the element parameter is passed, the function will begin the
# search at a given higher-level element inside the SSLv3/TLSv1 record
# found at the offset.
#
# @param blob A stream of records
# @param element Index of an element inside a record
# @param encrypted Boolean indicated whether the record is encrypted,
#                  false by default
# @param offset Byte offset at which to begin parsing
#
# @anonparam field Field in record, must be followed by a value
# @anonparam value Value of field, must be preceded by a field
#
# @return An array representing the first record that matched the
#         given filters, or NULL if no match was found.
##
function ssl_find(blob, element, encrypted, offset)
{
  local_var filter, i, key, passed, rec, value;

  # Sanity check arguments.
  if ( isnull(blob) ) return NULL;
  if ( isnull(offset) ) offset = 0;
  if ( isnull(element) ) element = 0;

  # Make anonymous arguments into a filter.
  filter = make_array();
  for ( i = 0; i < max_index(_FCT_ANON_ARGS); i += 2 )
    filter[_FCT_ANON_ARGS[i]] = _FCT_ANON_ARGS[i + 1];

  while ( offset < strlen(blob) )
  {
    for ( i = element; TRUE; i++ )
    {
      # Get the next record in the stream.
      rec = ssl_parse(blob:blob, element:i, encrypted:encrypted, offset:offset);
      if ( isnull(rec) ) return NULL;
      if ( typeof(rec) == "int" ) break;

      # Test the record against all the filters.
      passed = TRUE;
      foreach key ( keys(filter) )
      {
        value = rec[key];
        if ( ! isnull(value) && value == filter[key] ) continue;

        passed = FALSE;
        break;
      }

      # If all the filters passed, we've found our target.
      if ( passed ) return rec;
    }

    # While we may have wanted to start searching partway into a
    # record, we want to start at the first element of subsequent
    # records.
    element = 0;
    offset = rec;
  }

  return NULL;
}

function ssl2_handshake(exit_on_fail, port, socket, transport)
{
  local_var inner, middle, msg, offset, outer, pair, rec, recs, result;

  # Provide defaults for arguments.
  if ( isnull(exit_on_fail) ) exit_on_fail = FALSE;

  # Ensure we're going to have the functions we need.
  if ( nasl_level() < 3210 )
  {
    if ( exit_on_fail ) exit(0);
    else return NULL;
  }

  # Make sure we support the encapsulation method this port uses.
  if ( transport != ENCAPS_SSLv2 )
  {
    msg = "Unsupported encapsulation method.";
    if ( exit_on_fail ) exit(1, msg);
    debug_print(msg);
    return NULL;
  }

  # The three sockets we use will be arranged as follows:
  #   inner <-> middle <-> MITM code <-> outer <-> target
  pair = socketpair();
  inner = pair[0];
  middle = pair[1];

  outer = socket;
  if ( isnull(outer) )
  {
    # We need a port if we weren't given a socket.
    if ( isnull(port) )
    {
      msg = "Port not specified and socket not provided.";
      if ( exit_on_fail ) exit(1, msg);
      debug_print(msg);
      close(inner);
      close(middle);
      return NULL;
    }

    outer = open_sock_tcp(port, transport:ENCAPS_IP);
    if ( ! outer )
    {
      msg = "Port "+port+" is not open.";
      if ( exit_on_fail ) exit(1, msg);
      debug_print(msg);
      close(inner);
      close(middle);
      return NULL;
    }
  }

  # Collect all SSL records to return to caller.
  result = "";

  # Receive handshake part 1 of 5:
  #   ClientHello
  socket_negotiate_ssl(socket:inner, transport:transport, async:TRUE);
  socket_ready(inner);
  recs = recv_ssl(socket:middle);
  if ( recs == "" )
  {
    msg = "Error generating ClientHello.";
    if ( exit_on_fail ) exit(1, msg);
    debug_print(msg);
    close(inner);
    close(middle);
    if ( isnull(socket) ) close(outer);
    return NULL;
  }
  send(socket:outer, data:recs);
  result += recs;

  # Receive handshake part 2 of 5:
  #   ServerHello
  recs = recv_ssl(socket:outer);
  if ( recs == "" )
  {
    msg = "Target didn't respond to ClientHello.";
    if ( exit_on_fail ) exit(1, msg);
    debug_print(msg);
    close(inner);
    close(middle);
    if ( isnull(socket) ) close(outer);
    return NULL;
  }
  socket_ready(inner);
  send(socket:middle, data:recs);
  result += recs;

  # Need to give OpenSSL a moment, otherwise we don't get a response.
  sleep(1);

  # Receive handshake part 3 of 5:
  #   ClientMasterKey
  socket_ready(inner);
  recs = recv_ssl(socket:middle);
  if ( recs == "" )
  {
    msg = "OpenSSL didn't respond to ServerHello.";
    if ( exit_on_fail ) exit(1, msg);
    debug_print(msg);
    close(inner);
    close(middle);
    if ( isnull(socket) ) close(outer);
    return NULL;
  }
  send(socket:outer, data:recs);
  result += recs;

  # Receive handshake part 4 of 5:
  #   (Opaque)
  recs = recv_ssl(socket:outer);
  if ( recs == "" )
  {
    msg = "Target didn't respond to ClientMasterKey.";
    if ( exit_on_fail ) exit(1, msg);
    debug_print(msg);
    close(inner);
    close(middle);
    if ( isnull(socket) ) close(outer);
    return NULL;
  }
  socket_ready(inner);
  send(socket:middle, data:recs);
  result += recs;

  # Receive handshake part 5 of 5:
  #   (Opaque)
  socket_ready(inner);
  recs = recv_ssl(socket:middle);
  if ( recs == "" )
  {
    msg = "OpenSSL didn't respond to fourth record.";
    if ( exit_on_fail ) exit(1, msg);
    debug_print(msg);
    close(inner);
    close(middle);
    if ( isnull(socket) ) close(outer);
    return NULL;
  }
  send(socket:outer, data:recs);
  result += recs;

  # Close our initial session. This will not perform a proper SSL
  # shutdown.
  close(inner);
  close(middle);

  # Only close the outer socket if we made it ourselves.
  if ( isnull(socket) ) close(outer);

  return result;
}

function ssl3_handshake(exit_on_fail, port, socket, transport)
{
  local_var inner, middle, msg, offset, outer, pair, rec, recs, result;

  # Provide defaults for arguments.
  if ( isnull(exit_on_fail) ) exit_on_fail = FALSE;

  # Ensure we're going to have the functions we need.
  if ( nasl_level() < 3210 )
  {
    if ( exit_on_fail ) exit(0);
    else return NULL;
  }

  # Make sure we support the encapsulation method this port uses.
  if ( transport != ENCAPS_SSLv3 && transport != ENCAPS_TLSv1 )
  {
    msg = "Unsupported encapsulation method.";
    if ( exit_on_fail ) exit(1, msg);
    debug_print(msg);
    return NULL;
  }

  # The three sockets we use will be arranged as follows:
  #   inner <-> middle <-> MITM code <-> outer <-> target
  pair = socketpair();
  inner = pair[0];
  middle = pair[1];

  outer = socket;
  if ( isnull(outer) )
  {
    # We need a port if we weren't given a socket.
    if ( isnull(port) )
    {
      msg = "Port not specified and socket not provided.";
      if ( exit_on_fail ) exit(1, msg);
      debug_print(msg);
      close(inner);
      close(middle);
      return NULL;
    }

    outer = open_sock_tcp(port, transport:ENCAPS_IP);
    if ( ! outer )
    {
      msg = "Port "+port+" is not open.";
      if ( exit_on_fail ) exit(1, msg);
      debug_print(msg);
      close(inner);
      close(middle);
      return NULL;
    }
  }

  # Collect all SSL records to return to caller.
  result = "";

  # Receive handshake part 1 of 4:
  #   ClientHello
  socket_negotiate_ssl(socket:inner, transport:transport, async:TRUE);
  socket_ready(inner);
  recs = recv_ssl(socket:middle);
  if ( recs == "" )
  {
    msg = "Error generating ClientHello.";
    if ( exit_on_fail ) exit(1, msg);
    debug_print(msg);
    close(inner);
    close(middle);
    if ( isnull(socket) ) close(outer);
    return NULL;
  }
  send(socket:outer, data:recs);
  result += recs;

  # Receive handshake part 2 of 4:
  #   ServerHello, Certificate, ServerKeyExchange, ServerHelloDone
  recs = "";
  while ( TRUE )
  {
    rec = recv_ssl(socket:outer);
    if ( isnull(rec) ) break;
    recs += rec;

    socket_ready(inner);
    send(socket:middle, data:rec);

    rec = ssl_find(
      blob:rec,
      "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
      "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE
    );
    if ( ! isnull(rec) ) break;
  }
  if ( recs == "" )
  {
    msg = "Target didn't respond to ClientHello.";
    if ( exit_on_fail ) exit(1, msg);
    debug_print(msg);
    close(inner);
    close(middle);
    if ( isnull(socket) ) close(outer);
    return NULL;
  }
  result += recs;

  # Receive handshake part 3 of 4:
  #   ClientKeyExchange, ChangeCipherSpec, Finished
  socket_ready(inner);
  recs = "";
  while ( TRUE )
  {
    rec = recv_ssl(socket:middle);
    if ( isnull(rec) ) break;
    recs += rec;

    send(socket:outer, data:rec);

    rec = ssl_find(
      blob:rec,
      "content_type", SSL3_CONTENT_TYPE_CHANGECIPHERSPEC
    );
    if ( ! isnull(rec) ) break;
  }
  rec = recv_ssl(socket:middle);
  if ( isnull(rec) || recs == "" )
  {
    msg = "OpenSSL didn't accept target's ServerHello.";
    if ( exit_on_fail ) exit(1, msg);
    debug_print(msg);
    close(inner);
    close(middle);
    if ( isnull(socket) ) close(outer);
    return NULL;
  }
  recs += rec;
  send(socket:outer, data:rec);
  result += recs;

  # Receive handshake part 4 of 4:
  #   ChangeCipherSpec, Finished
  recs = "";
  while ( TRUE )
  {
    rec = recv_ssl(socket:outer);
    if ( isnull(rec) ) break;
    recs += rec;

    rec = ssl_find(
      blob:rec,
      "content_type", SSL3_CONTENT_TYPE_CHANGECIPHERSPEC
    );
    if ( ! isnull(rec) ) break;
  }
  rec = recv_ssl(socket:outer);
  recs += rec;
  if ( recs == "" )
  {
    msg = "Target didn't respond to Finished.";
    if ( exit_on_fail ) exit(1, msg);
    debug_print(msg);
    close(inner);
    close(middle);
    if ( isnull(socket) ) close(outer);
    return NULL;
  }
  result += recs;

  # Close our initial session. This will not perform a proper SSL
  # shutdown.
  close(inner);
  close(middle);

  # Only close the outer socket if we made it ourselves.
  if ( isnull(socket) ) close(outer);

  return result;
}

##
# TLS pseudorandom number generation function
#
# @param secret  - key to the HMAC function
# @param seed    - initial seed
# @param label   - label identifying the output data
# @param nb      - number of bytes to generate
#
# @return   <nb> bytes of pseudorandom numbers
#           or NULL if an error occurred
#
# @caveat only works for TLS 1.0, 1.1,
# TODO:   add support for TLS 1.2 ciphersuite-specified PRF
#
##
function tls_prf(secret, seed, label, nb, version)
{
  local_var data, slen, hslen, s1, s2;
  local_var i, j, k, hmac, A, out, result;

  if(isnull(version)) version = TLS_10;

  if(version < TLS_10 || version > TLS_12)
  {
    debug_print("tls_prf() does not support SSL version ", hexstr(mkword(version)), ".");
    return NULL;
  }

  data = label + seed;
  result = NULL;

  # Does not support ciphersuite-specified PRF from TLS 1.2. Only
  # supports the default of SHA256. Ciphersuites which do not specify
  # a PRF (e.g. existing ciphersuites from TLS 1.0 and 1.1) use this
  # default of SHA256 when they are used in TLS 1.2.
  if(version == TLS_12)
  {
    A = data; # A(0)
    for(i = 0; i < nb; i += 32)
    {
      A = HMAC_SHA256(key:secret, data:A); # A(i)
      result += HMAC_SHA256(key:secret, data:A + data);
    }
    return substr(result, 0, nb - 1);
  }

  if(strlen(secret) == 0)
    s1 = s2 = '';
  else # split secret into equal halves
  {
    slen = strlen(secret);
    hslen = (slen + 1)/2;

    s1 = substr(secret, 0, hslen - 1);
    s2 = substr(secret, slen - hslen, slen -1);
  }

  #
  # P_MD5(S1, label+seed)
  #
  # A(1)
  A = HMAC_MD5(key:s1, data:data);
  for(i = 0 ; i < nb; i += 16)
  {
    hmac = HMAC_MD5(key:s1, data:A + data);

    if ( i + 16 > nb )  k = nb % 16;
    else                k = 16;

    for( j = 0; j < k; j++ )
      out[i + j]  = hmac[j];

    A = HMAC_MD5(key:s1, data:A);
  }

  #
  # XOR with P_SHA1(S2, label+seed)
  #
  # A(1)
  A = HMAC_SHA1(key:s2, data:data);
  for(i = 0 ; i < nb; i += 20)
  {
    hmac = HMAC_SHA1(key:s2, data:A + data);
    if ( i + 20 > nb )  k = nb % 20;
    else                k = 20;

    for( j = 0; j < k; j++ )
      result  += raw_string(ord(out[i + j]) ^ ord(hmac[j]));

    A = HMAC_SHA1(key:s2, data:A);
  }

  return result;
}

##
# Computes the master secret from pre master secret and random values
#
# @param premaster  - premaster secret
# @param c_random   - 32-byte client random value
# @param s_random   - 32-byte server random value
# @param version    - TLS version   
#
# @return   48-byte master secret
# 
##
function tls_calc_master(premaster, c_random, s_random, version)
{
  local_var  master, seed;
  
  seed = c_random + s_random;
  
  master = tls_prf(secret:premaster, seed:seed,label:"master secret", nb:48, version:version);
  
  return master;
}

##
# Computes the master secret from pre master secret and random values
#
# @param premaster  - premaster secret
# @param c_random   - 32-byte client random value
# @param s_random   - 32-byte server random value
# @param version    - SSL version   
#
# @return   48-byte master secret
# 
##
function ssl_calc_master(premaster, c_random, s_random, version)
{
  local_var seed, master,sha1;

  if(isnull(version))
    version = SSL_V3;
  
  # SSL2 and below currently not supported
  if(version < SSL_V3)
    return NULL;
    
  if(version >= TLS_10)
    return tls_calc_master(premaster:premaster, c_random:c_random, s_random:s_random, version:version);
    
  # SSL v3
  # master =
  #       MD5( premaster + SHA1( 'A'   + premaster + randbytes ) ) +
  #       MD5( premaster + SHA1( 'BB'  + premaster + randbytes ) ) +
  #       MD5( premaster + SHA1( 'CCC' + premaster + randbytes ) )

  seed = c_random + s_random;
  master  = MD5(premaster + SHA1('A'  + premaster + seed)) +
            MD5(premaster + SHA1('BB' + premaster + seed)) +
            MD5(premaster + SHA1('CCC'+ premaster + seed));
            
  return master;
  
}

##
# Derives key material from the master secret
#
# @param master     - master secret
# @param c_random   - 32-byte client random value
# @param s_random   - 32-byte server random value
# @param nb         - number of bytes to generate
# @param version    - TLS version   
#
# @return   <nb>-byte key material for encryption, MAC, and IV
#           if <nb> is not specified, the default is 256 bytes
#           
##
function tls_derive_keyblk(master, c_random, s_random, nb,version)
{
  local_var  seed, keyblk;
  
  if(isnull(nb)) nb = 256;
  
  seed = s_random + c_random;
  keyblk= tls_prf(secret:master, seed:seed,label:"key expansion", nb:nb, version:version);
   
  return keyblk;
}

##
# Derives key material from the master secret
#
# @param master     - master secret
# @param c_random   - 32-byte client random value
# @param s_random   - 32-byte server random value
# @param nb         - number of bytes to generate
# @param version    - TLS version   
#
# @return   <nb>-byte key material for encryption, MAC, and IV
#           if <nb> is not specified, the default is 256 bytes
#           
##
function ssl_derive_keyblk(master, c_random, s_random, nb,version)
{
  local_var  seed, prefix,keyblk, i;
  
  # default to SSL v3
  if(isnull(version))
    version = SSL_V3;
  
  # SSL2 and below currently not supported
  if(version < SSL_V3)
    return NULL;
    
  if(isnull(nb)) nb = 256;
  
  if(version >= TLS_10)
    return tls_derive_keyblk(master:master, c_random:c_random, s_random:s_random, version:version);
    
  # SSL v3
  # key block =
  #   MD5( master + SHA1( 'A'    + master + randbytes ) ) +
  #   MD5( master + SHA1( 'BB'   + master + randbytes ) ) +
  #   MD5( master + SHA1( 'CCC'  + master + randbytes ) ) +
  #   MD5( master + SHA1( 'DDDD' + master + randbytes ) ) +
  #   ...
  
  keyblk = NULL;
  seed = s_random + c_random;
  for(i = 0; nb > 0; i++)
  {
    prefix = crap(data:mkbyte(ord('A') + i), length: i + 1);
    keyblk += MD5(master + SHA1(prefix+ master + seed));
    nb -= 16;  
  }
    
  return keyblk;
}

##
# compute the Finished message
#
# @param master     - master secret
# @param handshake  - all plaintext handshake messages concatenated, excluding the
#                     record layer headers and MACs (http://tools.ietf.org/html/rfc2246#section-7.4.9)
# @param version    - SSL version
# @param is_client  - is it the client side
#
# @return finished message
#
##
function ssl_calc_finished(master, handshake, is_client, version)
{
  local_var finished, sender, md5sum, sha1sum;

  # default to SSL v3
  if(isnull(version))
    version = SSL_V3;

  # SSL2 and below currently not supported
  if(version < SSL_V3)
    return NULL;

  #
  # SSLv3:
  # hash =
  #  MD5(  master + pad2 + MD5( handshake + sender + master + pad1 ) ) +
  #  SHA1( master + pad2 +SHA1( handshake + sender + master + pad1 ) )
  #
  #
  # TLSv1:
  #    hash = PRF( master, finished_label,MD5( handshake ) + SHA1( handshake ) )[0..11]
  #
  # TLSv12:
  #   hash = PRF( master, finished_labal, ciphersuite_hash(handshake))[0..n]
  #   nb: Supports only the default of P_SHA256, which is what all TLS1.0
  #   ciphers use when being used with TLS 1.2.
  if(version == SSL_V3)
  {
    if(is_client)
      sender = "CLNT";
    else
      sender = "SRVR";

    md5sum  = MD5( handshake + sender + master +  crap(data:'\x36',length:48));
    sha1sum = SHA1(handshake + sender + master +  crap(data:'\x36',length:40));

    finished = MD5( master + crap(data:'\x5c', length:48) + md5sum) +
               SHA1(master + crap(data:'\x5c', length:40) + sha1sum);
  }
  else if (version == TLS_10 || version == TLS_11)
  {
    if(is_client)
      sender = "client finished";
    else
      sender = "server finished";

    finished = tls_prf(secret:master, seed:MD5(handshake) + SHA1(handshake), label:sender, nb:12, version:version);
  }
  # Only supports the "default PRF" which is used with TLS 1.0 ciphers
  # when in TLS 1.2. Same as tls_prf function.
  else if (version == TLS_12)
  {
    if(is_client)
      sender = "client finished";
    else
      sender = "server finished";

    finished = tls_prf(secret:master, seed:SHA256(handshake), label:sender, nb:12, version:version);
  }

  return finished;
}

##
# Creates a TLS record
# 
# @param type     - record type
# @param data     - record data
# @param version  - TLS version
# 
# @return         an TLS record
#                 or NULL if an error occurred
##
function tls_mk_record(type, data, version)
{
  local_var rec, len;
  
  # default to TLS 1.0
  if(isnull(version)) version = TLS_10;
  
  if(version < TLS_10) return NULL;
  #if(isnull(data))     return NULL;
 
  return ssl_mk_record(type:type, data:data, version:version);
 
}

##
# Creates a SSL record,
# 
# @param type     - record type
# @param data     - record data
# @param version  - SSL version
# 
# @return         an TLS record
#                 or NULL if an error occurred
##
function ssl_mk_record(type, data, version)
{
  local_var rec, len;
  
  # default to SSL 3
  if(isnull(version)) version = SSL_V3;
  
  if(version < SSL_V3)
  {
    debug_print("ssl_mk_record() does not support SSL version 2 or below.\n");
    return NULL;
  }
  
  # allow empty records
  #if(isnull(data))     return NULL;
  
  version = mkbyte((version >>> 8) & 0xff) + mkbyte(version & 0xff);
  
  len = strlen(data);
  
  # max record size
  if(len > 16384) return NULL;
  
  len = mkbyte((len >>> 8) & 0xff) + mkbyte(len & 0xff);
  
  type = mkbyte(type);
  
  rec = type + version + len + data;

  return rec;
}

##
# Creates a TLS handshake message
# 
# @param type     - handshake message type
# @param data     - handshake message data
# 
# @return         a handshake message
#                 or NULL if an error occurred
##
function tls_mk_handshake_msg(type, data)
{
 return ssl_mk_handshake_msg(type:type, data:data);
}

##
# Creates a SSL handshake message
# 
# @param type     - handshake message type
# @param data     - handshake message data
# 
# @return         a handshake message
#                 or NULL if an error occurred
##
function ssl_mk_handshake_msg(type, data)
{
  local_var len, msg;
  
  #if(isnull(data)) return NULL;
  if(isnull(type)) return NULL;
  
  type = mkbyte(type);
  
  len = strlen(data);
  len = mkbyte((len >>> 16) & 0xff) + mkbyte((len >>> 8) & 0xff) + mkbyte(len & 0xff);
  
  msg = type + len + data;
  
  return msg;
}

##
# Reorders and filters certificate chains.
#
# Certificate chains should be ordered in ascending order from the
# lowest-level certificate which signs no others, then through
# intermediate CAs, ending with a root CA. This function sorts
# certificate chains to match that ordering, filtering out extraneous
# certificates in the process.
#
# @anonparam chain The certificate chain, either parsed or raw.
#
# @param filter If true (default) don't return unused certificates.
# @param raw    If true (default) return certificates in raw format.
#
# @remark If a chain of parsed certificates are passed in, the raw
#         parameter cannot be used.
#
# @return The certificate chain in ascending order.
##
function sort_cert_chain(filter, raw)
{
  local_var bottom, ca, cert, certs, chain_arr, chain_str, found, i;
  local_var n, nonsigners, res, signed, sorted, top, unused, used;

  # Process arguments.
  chain_str = _FCT_ANON_ARGS[0];
  if (isnull(chain_str))
    return NULL;
  if (isnull(filter))
    filter = TRUE;
  if (isnull(raw))
    raw = TRUE;

  # Parse each certificate in the chain so that we can access their
  # fields to compare subjects and issuers.
  chain_arr = parse_cert_chain(chain_str);
  if (isnull(chain_arr))
    return NULL;

  # Since we can make no assumptions about what is in this chain, we
  # need to find the bottom of the chain by looking for certificates
  # that are not used to sign other certificates.
  bottom = NULL;

  for (i = 0; i < max_index(chain_arr); i++)
  {
    # Check if the certificate we're looking at has signed any of the
    # certificates in the chain, including itself.
    signed = FALSE;

    foreach cert (chain_arr)
    {
      if (is_signed_by(cert, chain_arr[i]))
      {
        signed = TRUE;
        break;
      }
    }

    # If the certificate hasn't signed any others, including itself,
    # it is a candidate for the bottom of the chain.
    if (!signed)
    {
      bottom = i;
      break;
    }
  }

  # If there was no bottom, it means that we either have a self-signed
  # certificate, or there is a signing loop of some sort.
  if (isnull(bottom))
  {
    for (i = 0; i < max_index(chain_arr); i++)
    {
      if (is_self_signed(chain_arr[i]))
      {
        bottom = i;
        break;
      }
    }

    # If there was no bottom, and no self-signed certs, we have a loop
    # which is something this function can't handle.
    if (isnull(bottom))
      return NULL;

    # The sorted chain will consist of only the self-signed certificate.
    sorted = make_list(bottom);
  }
  else
  {
    # Regardless of how many candidates there were for the bottom of
    # the chain, we've arbitrarily pick the first one we encountered
    # in the unsorted chain.
    n = 0;
    sorted = make_list();
    sorted[n++] = bottom;

    # From here on, we build up the rest of the chain by connecting
    # issuers to subjects. Theoretically a chain can branch and merge,
    # but we're only interested in a linear path, so we'll cut out
    # everything but the shortest path from the bottom cert to the
    # root CA.
    while (TRUE)
    {
      # Extract the issuer that we're looking for from the certificate
      # at the top of the current chain.
      top = sorted[n - 1];

      # Look for a certificate in the chain with a subject that
      # matches the issuer.
      i = find_issuer_idx(CA:chain_arr, cert:chain_arr[top]);

      # If the issuer is missing, it's considered as an unknown CA, so
      # we end the chain.
      if (i < 0)
        break;

      # A self-signed certificate will end the chain.
      if (i == top)
        break;

      # Add the issuer to the top of the sorted chain.
      sorted[n++] = i;
    }
  }

  # The caller either expects an array of parsed or unparsed certs.
  if (raw)
    certs = chain_str;
  else
    certs = chain_arr;

  # At this point we have the indexes of certificates that form the
  # sorted chain.
  n = 0;
  used = make_list();

  for (i = 0; i < max_index(sorted); i++)
  {
    used[n++] = certs[sorted[i]];
  }

  # Return only the certificates that are required to make a linear
  # chain.
  if (filter)
    return used;

  # If the caller requested unused certificates as well, we'll now
  # create an array for those.
  n = 0;
  unused = make_list();

  for (i = 0; i < max_index(certs); i++)
  {
    found = FALSE;

    foreach cert (sorted)
    {
      if (cert == i)
      {
        found = TRUE;
        break;
      }
    }

    if (!found)
      unused[n++] = certs[i];
  }

  # Return all the certificates.
  res = make_list();
  res[0] = used;
  res[1] = unused;

  return res;
}

function cipher_name(id, encaps, pretty)
{
  local_var cipher, i, len, name, type;

  # Sanity check parameters.
  if (isnull(id)) return NULL;

  # Set defaults.
  if (isnull(pretty)) pretty = FALSE;

  name = NULL;

  # Convert the cipher from whatever representation we were given to a
  # name.
  type = typeof(id);
  if (type == "int")
  {
    id = mkword(id);
  }
  else if (type == "data" || type == "string")
  {
    # All ciphers are represented by either two or three bytes.
    # Anything longer than that is probably already the name of a
    # cipher.
    len = strlen(id);
    if (len < 2) return NULL;
    if (len > 3) name = id;
  }
  else
  {
    return NULL;
  }

  # Try to match encapsulation to a similarly named cipher.
  #
  # Sometimes SSL and TLS use each other's ciphers. If we can't find a
  # matching cipher the first time, remove the name restrictions and
  # try again.
  for (i = 0; i < 2 && isnull(name); i++)
  {
    # Skip the phase of comparing cipher names to encapsulations if we
    # don't know what encapsulation is being used.
    if (i == 0 && isnull(encaps)) continue;

    foreach cipher (sort(keys(ciphers)))
    {
      # Skip ciphers that don't match transport.
      if (i == 0)
      {
        if (encaps == ENCAPS_SSLv2 && "SSL2_" >!< cipher) continue;
        if (encaps == ENCAPS_SSLv3 && "SSL3_" >!< cipher) continue;
        if (encaps == ENCAPS_TLSv1 && "TLS1_" >!< cipher) continue;
        if (encaps == COMPAT_ENCAPS_TLSv11 && cipher !~ "^TLS11?_") continue;
        if (encaps == COMPAT_ENCAPS_TLSv12 && cipher !~ "^TLS12?_") continue;
      }

      if (ciphers[cipher] == id)
      {
        name = cipher;
        break;
      }
    }
  }

  if (isnull(name)) name = "Unknown";

  if (pretty)
  {
    if (type != "int") id = ciphers[name];
    if (!isnull(id)) name += ' (0x' + hexstr(id) + ')';
  }

  return name;
}

###
# These are the relative strengths of ciphers, categorized by key
# length.
###
global_var CIPHER_STRENGTH_NULL, CIPHER_STRENGTH_LOW, CIPHER_STRENGTH_MEDIUM, CIPHER_STRENGTH_HIGH, CIPHER_STRENGTH_MAX;

CIPHER_STRENGTH_NULL   = 0; # = 0-bit key
CIPHER_STRENGTH_LOW    = 1; # <= 64-bit key
CIPHER_STRENGTH_MEDIUM = 2; # > 64-bit and < 112-bit key
CIPHER_STRENGTH_HIGH   = 3; # > 112-bit key
CIPHER_STRENGTH_MAX    = 4; # Unknown key

##
# Categorizes the strength of a cipher, using key length as a
# heuristic.
#
# @param encaps Encapsulation type corresponding to the cipher
#
# @anonparam cipher Cipher to categorize
#
# @return A constant representing the strength of the cipher.
##
function cipher_strength(encaps)
{
  local_var bits, desc, len, matches, name;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  # Get the name of the cipher, since that's the key for all the
  # cipher arrays.
  name = cipher_name(id:_FCT_ANON_ARGS[0], encaps:encaps);
  if (isnull(name))
    return NULL;

  # Get the text description of the cipher. If we can't find a
  # description for a cipher, we assume it's the maximum strength.
  desc = ciphers_desc[name];
  if (isnull(desc))
    return CIPHER_STRENGTH_MAX;

  if ("Enc=None" >< desc)
    return CIPHER_STRENGTH_NULL;

  if ("Enc=AES" >< desc)
    return CIPHER_STRENGTH_HIGH;

  # 3DES to Medium because of CVE-2016-2183.
  if ("Enc=3DES-CBC" >< desc)
  	return CIPHER_STRENGTH_MEDIUM;
  	
  # Parse the key length from the description.
  matches = eregmatch(string:desc, pattern:".*Enc=[^|]+\(([0-9]+)\).*");
  if (isnull(matches))
    return CIPHER_STRENGTH_MAX;

  bits = int(matches[1]);

  if (bits == 0)
    return CIPHER_STRENGTH_NULL;

  if (bits <= 64)
    return CIPHER_STRENGTH_LOW;

  if (bits < 112)
    return CIPHER_STRENGTH_MEDIUM;

  return CIPHER_STRENGTH_HIGH;
}

##
# Compares the strength of two ciphers.
#
# @anonparam c1 First cipher to compare
# @anonparam c2 Second cipher to compare
#
# @return -1 (c1 is weaker), 0 (equal strength), or 1 (c1 is stronger).
##
function cipher_cmp()
{
  local_var c1, c2, s1, s2;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 2)
    return NULL;

  c1 = _FCT_ANON_ARGS[0];
  c2 = _FCT_ANON_ARGS[1];

  # Check if we're comparing a cipher to itself.
  if (c1 == c2)
    return 0;

  # Get the strength of each cipher.
  s1 = cipher_strength(c1);
  if (isnull(s1))
    return NULL;

  s2 = cipher_strength(c2);
  if (isnull(s2))
    return NULL;

  # Compare the strengths.
  if (s1 < s2)
    return -1;

  if (s1 > s2)
    return 1;

  return 0;
}

##
# Create a report of the selected ciphers.
#
# @param desc Only report on ciphers whose name matches regex
# @param eq   Only report on ciphers equal to this strength
# @param max  Only report on ciphers less than this strength
# @param min  Only report on ciphers greater than this strength
# @param name Only report on ciphers whose description matches regex
#
# @anonparam ciphers List of ciphers to process
#
# @return A formatted report of the selected ciphers.
##
function cipher_report(desc, eq, max, min, name)
{
  local_var cipher, col, field, fields, i, labels, list, protocol;
  local_var protocols, report, reports, strength;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  list = _FCT_ANON_ARGS[0];

  # Format and categorize ciphers.
  reports = make_array();
  foreach cipher (sort(list))
  {
    # Find the strength of the cipher.
    strength = cipher_strength(cipher);
    if (isnull(strength))
      continue;

    # Filter based on the regex, if given.
    if (!isnull(desc) && ciphers_desc[cipher] !~ desc)
      continue;

    if (!isnull(name) && cipher !~ name)
      continue;

    # Filter the cipher if it's outside our bounds.
    if (!isnull(eq) && strength != eq)
      continue;

    if (!isnull(min) && strength < min)
      continue;

    if (!isnull(max) && strength > max)
      continue;

    # We don't have descriptions for maximum strength ciphers.
    if (strength == CIPHER_STRENGTH_MAX)
    {
      protocol = "Unknown Protocol";
    }
    else
    {
      # Extract fields from cipher's description.
      fields = split(ciphers_desc[cipher], sep:"|", keep:FALSE);
      protocol = fields[1];
    }

    # Initialize the report for ciphers of this strength.
    if (isnull(reports[strength]))
      reports[strength] = make_array();

    # Initialize the report for ciphers of this protocol.
    if (isnull(reports[strength][protocol]))
      reports[strength][protocol] = "";

    # We don't have descriptions for maximum strength ciphers.
    if (strength == CIPHER_STRENGTH_MAX)
    {
      reports[strength][protocol] += '      ' + cipher + '\n';
      continue;
    }

    i = 0;
    report = "";
    foreach field (fields)
    {
      # Determine proper alignment for column.
      if (i == 0) col = 27;
      else if (i == 2) col = 13;
      else if (i == 3) col = 10;
      else if (i == 4) col = 23;
      else col = 9;

      if (col < strlen(field))
        col = strlen(field);

      # Add column to report for this cipher.
      if (i != 1)
        report += field + crap(data:" ", length:col - strlen(field)) + "  ";

      i++;
    }

    reports[strength][protocol] += '      ' + report + '\n';
  }

  # Skip generating a report if no ciphers matched our conditions.
  if (max_index(keys(reports)) == 0)
    return NULL;

  # Flatten the report.
  labels = make_array(
    CIPHER_STRENGTH_NULL, "Null Ciphers (no encryption)",
    CIPHER_STRENGTH_LOW, "Low Strength Ciphers (<= 64-bit key)",
    CIPHER_STRENGTH_MEDIUM, "Medium Strength Ciphers (> 64-bit and < 112-bit key, or 3DES)",
    CIPHER_STRENGTH_HIGH, "High Strength Ciphers (>= 112-bit key)",
    CIPHER_STRENGTH_MAX, "Unrecognized Ciphers"
  );
  protocols = make_list(
    "SSLv2",
    "SSLv3",
    "TLSv1",
    "TLSv11",
    "TLSv12",
    "Unknown Protocol"
  );

  report = "";
  foreach strength (sort(keys(reports)))
  {
    # Add the label for ciphers of a certain strength.
    report += '  ' + labels[strength] + '\n\n';

    foreach protocol (protocols)
    {
      if (!isnull(reports[strength][protocol]))
        report += '    ' + protocol + '\n' + reports[strength][protocol] + '\n';
    }
  }

  # Generate report.
  return
    '\n' + report +
    'The fields above are :' +
    '\n' +
    '\n  {OpenSSL ciphername}' +
    '\n  Kx={key exchange}' +
    '\n  Au={authentication}' +
    '\n  Enc={symmetric encryption method}' +
    '\n  Mac={message authentication code}' +
    '\n  {export flag}' +
    '\n';
}

##
# Converts a raw certificate to PEM format.
#
# @anonparam cert The raw certificate.
#
# @return The certificate in PEM format.
##
function blob_to_pem()
{
  local_var cert;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  cert = _FCT_ANON_ARGS[0];

  return
    '-----BEGIN CERTIFICATE-----\n' +
    ereg_replace(
      string  : base64(str:cert),
      pattern : "(.{1,64})",
      replace : '\\1\n'
    ) +
    '-----END CERTIFICATE-----\n';
}

##
# Converts a PEM certificate to raw format.
#
# @anonparam blob The PEM certificate.
#
# @return The raw certificate.
##
function pem_to_blob()
{
  local_var blob, cert, line;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  blob = _FCT_ANON_ARGS[0];

  cert = "";
  foreach line (split(blob, keep:FALSE))
  {
    if (line !~ "^-+(BEGIN|END) CERTIFICATE-+$")
      cert += line;
  }

  return base64_decode(str:cert);
}

##
# Formats certificates to be suitable for reports.
#
# @anonparam certs The certificates to be included in the report.
#
# @param chain Whether the report represents a certificate chain, true
#              by default.
#
# @return The formatted certificate report.
##
function cert_report(chain)
{
  local_var bar, certs, i, len, line, report;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  # Set defaults.
  if (isnull(chain))
    chain = TRUE;

  certs = _FCT_ANON_ARGS[0];

  bar = "|-";
  report = "";
  len = max_index(certs);

  # Walk the chain from the top downwards.
  for (i = len - 1; i >= 0; i--)
  {
    # Format each of the certificate's attributes.
    foreach line (split(certs[i]))
    {
      # Skip blank lines.
      if (line =~ "^ *$")
        continue;

      report += ereg_replace(string:line, pattern:"^", replace:bar);
    }

    if (chain)
      bar += "-";

    if (i != 0)
    {
      if (chain)
        report += "|";
      report += '\n';
    }
  }

  return report;
}

##
# Opens a socket for SSL communication.
#
# This function will open a raw TCP connection to the given port. If
# the port supports StartTLS, the proper command(s) will be given to
# bring the socket to the point at which SSL negotiation is possible.
# If an encapsulation method is declared, that encapsulation method
# will be negotiated. Otherwise, the raw socket will be returned.
#
# @anonparam port The TCP port to attempt connecting to.
#
# @param encaps The encapsulation method to negotiate.
#
# @return The opened socket.
##
function open_sock_ssl(encaps)
{
  local_var key, port, ret, soc, starttls, svc;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  port = _FCT_ANON_ARGS[0];

  # Open a socket, explicitly stating that we don't want Nessus to
  # negotiate SSL.
  soc = open_sock_tcp(port, transport:ENCAPS_IP);
  if (!soc)
    return NULL;
  # Check if this port is StartTLS.
  key = "/" + port + "/starttls";
  starttls = get_kb_list("*" + key);

  # If the port is straight SSL/TLS, perform the negotiation if we
  # were asked to by the caller.
  if (isnull(starttls))
  {
    if (isnull(encaps) || encaps == ENCAPS_IP)
      return soc;

    if (!defined_func("socket_negotiate_ssl"))
      return NULL;

    return socket_negotiate_ssl(socket:soc, transport:encaps);
  }

  # If there is more than one service declared on this port, we have
  # no way to decide what kind of StartTLS command to send, so fail.
  starttls = keys(starttls);
  if (max_index(starttls) > 1)
    return NULL;

  # Extract the service name and send the proper StartTLS commands.
  ret = NULL;
  svc = starttls[0] - key;
  if (svc == "acap")
    ret = acap_starttls(socket:soc, encaps:encaps);
  else if (svc == "amqp")
    ret = amqp_starttls(socket:soc, encaps:encaps);
  else if (svc == "ftp")
    ret = ftp_starttls(socket:soc, encaps:encaps);
  else if (svc == "imap")
    ret = imap_starttls(socket:soc, encaps:encaps);
  else if (svc == "ldap")
  {
    ldap_init(socket:soc);
    ret = ldap_starttls();
  }
  else if (svc == "mssql")
    ret = mssql_starttls(socket:soc, encaps:encaps);
  else if (svc == "nntp")
    ret = nntp_starttls(socket:soc, encaps:encaps);
  else if (svc == "nut")
    ret = nut_starttls(socket:soc, encaps:encaps);
  else if (svc == "pop3")
    ret = pop3_starttls(socket:soc, encaps:encaps);
  else if (svc == "rdp")
    ret = rdp_starttls(socket:soc, encaps:encaps);
  else if (svc == "smtp")
    ret = smtp_starttls(socket:soc, encaps:encaps);
  else if (svc == "telnet")
    ret = telnet_starttls(socket:soc, encaps:encaps);
  else if (svc == "xmpp")
    ret = xmpp_starttls(socket:soc, encaps:encaps);
  else if (svc == "irc")
    ret = ircd_starttls(socket:soc, encaps:encaps);
  else if (svc == "rsyncd")
  {
    rsync_init(socket:soc);
    ret = rsync_starttls(socket:soc, encaps:encaps);
  }
  # Service not supported
  else
  {
    close(soc);
    return NULL;
  }

  if (!ret)
  {
    # If socket_negotiate_ssl() fails, the underlying TCP socket is
    # closed automatically, so no need to close the socket if
    # xxx_starttls() is instructed to call socket_negotiate_ssl() via
    # the encaps param.
    if (!encaps)
      close(soc);
  }

  return ret;
}

##
# Find all ports that support SSL, either directly or with StartTLS.
#
# @param fork     Whether we should fork and return one port per
#                 child, false by default.
# @param ssl      Include SSL ports, true by default.
# @param starttls Include StartTLS ports, true by default.
#
# @return A list of ports supporting SSL.
##
function get_ssl_ports(fork, ssl, starttls)
{
  local_var key, list, port, ports;

  # Set defaults.
  if (isnull(fork))
    fork = FALSE;

  if (isnull(ssl))
    ssl = TRUE;

  if (isnull(starttls))
    starttls = TRUE;

  # Sanity check parameters.
  if (!ssl && !starttls)
    return NULL;

  ports = make_list();

  # Get list of ports that use SSL.
  if (ssl)
  {
    list = get_kb_list("Transport/SSL");
    if (!isnull(list))
      ports = make_list(list);
  }

  if (!starttls)
    return branch(ports, fork:fork);

  # Get list of ports that use StartTLS.
  list = get_kb_list("*/*/starttls");
  if (isnull(list))
    return branch(ports, fork:fork);

  foreach key (keys(list))
  {
    # Extract port from KB item name.
    port = split(key, sep:"/", keep:FALSE);
    port = int(port[1]);

    # Ignore invalid ports.
    if (port < 1 || port > 65535)
      continue;

    ports = add_port_in_list(list:ports, port:port);
  }

  return branch(ports, fork:fork);
}

##
# Parse a list of certificates.
#
# @param chain A list of certificates.
#
# @remark This function will correctly handle lists containing both
#         unparsed (data or string) and parsed (array) elements.
#
# @return A list of parsed certificates.
##
function parse_cert_chain()
{
  local_var chain, i, parsed, raw;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  chain = _FCT_ANON_ARGS[0];

  for (i = 0; i < max_index(chain); i++)
  {
    raw = chain[i];

    # Skip parsed certs.
    if (typeof(raw) == "array")
      continue;

    # Parse raw certificate.
    parsed = parse_der_cert(cert:raw);
    if (isnull(parsed))
      return NULL;
    parsed["raw"] = raw;

    # Replace raw cert with parsed cert.
    chain[i] = parsed;
  }

  return chain;
}

##
# Versions before 6.4
# Return versions TLSv1 when SSL is enabled
# Return ENCAPS_IP when SSL is disabled
#
# Version 6.4 and later 
# Prepares SSL transport using all TLS versions 
# and disabling SSLv3 and lower when SSL is enabled.
# ENCAPS_SSLv23 # enable all versions of SSL
# ENCAPS_DISABLE_SSLv3 # disable all below SSLv3
# ENCAPS_IP = TCP when SSL is disabled
# 
# @param ssl Sets SSL flag, default TRUE.
# @param verify Sets verification flag, default FALSE.
#
# @return Transport flags for the connection.
##
function ssl_transport(ssl, verify)
{
  if (isnull(ssl))
    ssl = TRUE;

  if (isnull(verify))
    verify = FALSE;

  if (!ssl)
    return ENCAPS_IP;

  if (nasl_level() < 6400)
  {
    if (!verify)
      return ENCAPS_TLSv1;

    return ENCAPS_TLSv1 | ENCAPS_VERIFY_PEER;
  }
  else 
  {
    if (!verify)
      return ENCAPS_SSLv23 | COMPAT_ENCAPS_DISABLE_SSLv3;

    return ENCAPS_SSLv23 | COMPAT_ENCAPS_DISABLE_SSLv3 | ENCAPS_VERIFY_PEER;
  }
}

##
# Creates a TLS extension
# 
# @param type extension type
# @param len  extension len, defaulted to strlen(data) 
# @param data extension data
# @return formatted TLS extension
#
##
function tls_ext(type, len, data)
{
  local_var ext;

  if(isnull(len))
    len = strlen(data);

  ext = raw_string((type >> 8) & 0xff, type & 0xff) +
        raw_string((len >> 8) & 0xff, len & 0xff) +
        data;
        
  return ext; 
}

##
# Create a TLSv1.2 Signature Algorithm Extension
#
# @anonparam a list of signature algorithms 
# @returned a formatted Signature Algorithm TLSv1.2 extension
# @remark if the algorithm list is not specified, a default list is used.
#
##
function tls_ext_sig_algs()
{
  local_var ext, list, hash;

  list = _FCT_ANON_ARGS[0];
  if(isnull(list))
  {
    list = make_list(
      0x0201,
      0x0203,
      0x0202,
      0x0401,
      0x0403,
      0x0501,
      0x0503,
      0x0601,
      0x0603
    );
  }
  foreach hash (list)
    ext += raw_string((hash >> 8) & 0xff, hash & 0xff);

  ext = ssl_vldata_put(data:ext, len:2);

  return tls_ext(type:13, data:ext);
}

##
# Creates a elliptic_curves TLS extension
#
# @anonparam a list of named elliptic curves 
# @returned a formatted elliptic_curves TLS extension
# @remark if the curve list is not specified, a default list is used.
#
##
function tls_ext_ec()
{
  local_var curve, ext, list;
  
  list = _FCT_ANON_ARGS[0];
  
  if(isnull(list))
  {
    # See TLS IANA registry for the most recent list
    list = make_list(
                      1, 2, 3, 4, 5, 6, 7, 8,
                      9, 10, 11, 12, 13, 14, 15, 16,
                      17, 18, 19, 20, 21, 22, 23, 24,
                      25, 26, 27, 28,
                      0xFF01, 0xFF02 
                    );
  } 

  ext = NULL;
  foreach curve (list)
  {
    ext += raw_string((curve >> 8) & 0xff, curve & 0xff);
  } 

  # Encode EllipticCurveList
  #      struct {
  #          NamedCurve elliptic_curve_list<1..2^16-1>
  #      } EllipticCurveList;
  ext = ssl_vldata_put(data:ext, len:2);

 
  return tls_ext(type: 10, data: ext); 
}

##
# Creates a ec_point_formats TLS extension
#
# @anonparam a list of named elliptic curves 
# @returned a formatted ec_point_formats TLS extension
# @remark if the format list is not specified, a default list is used.
#
##
function tls_ext_ec_pt_fmt()
{
  local_var fmt, ext, list;
  
  list = _FCT_ANON_ARGS[0];
  
  if(isnull(list))
  {
    # See TLS IANA registry for the most recent list
    list = make_list(0, 1, 2);
  } 

  ext = NULL;
  foreach fmt (list)
  {
    ext += raw_string(fmt);
  } 

  # Encode ECPointFormatList
  #        struct {
  #          ECPointFormat ec_point_format_list<1..2^8-1>
  #      } ECPointFormatList;
  ext = ssl_vldata_put(data:ext, len:1);

 
  return tls_ext(type: 11, data: ext); 
}

##
# Determines whether a cipher suite uses Elliptic Curve Cryptography 
# 
# @anonparam cipher suite name
# @return TRUE/FALSE
#
##
function tls_is_ec_cipher()
{
  local_var cipher;

  cipher = _FCT_ANON_ARGS[0];
  
  if('_EC' >< cipher) return TRUE;
  
  return FALSE;
}
