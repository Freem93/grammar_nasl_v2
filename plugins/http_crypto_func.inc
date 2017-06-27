#TRUSTED 5244d44a31692d5b4b6c93624c59fb913569361d8fcfc8f1f2d297006b92731ed3d9b5b5530ec3bc5fe589e2847de5557c5a2a6cfc8d39830876cc63eab2c9141957fe87be59e1e0886390fd12422a943d6c573912bd2fa957a608e8692b3d91ce440b0dc909372a51f398de2b0b67876f71a94501a26440b30f82cd44d4e8e5821113c7d2654e45511e2847df02293ed964ccd61e8cd5e4d8a0772435963c2d45f9383a91832091fec02090bf3b868884fc476d176b05ab308fec11c346bc18dacd5aa04d058f442da66a106ba81031da60faaa77cc81004616c6efdcf2797392da6f7af8694c9156659d4a38a31a48c2c8226a7d21494813b84eaf1be116e4981204e12b7b89c7d8576f8f29eadcf50ba63d04fa1eec0d58da75fb7cb3d62ae45a1509abe3ad17216c7ab947b57550315fdd487f6155da8bda97c0f7b82f706d304e0f28f8adb5a62a1f98c1b4aa9996e9f4dd5510e880c7c2c5badfd54c456aef01f0900f589e25962cdb70f1bf24f8ef695b0db428aef7ad3c58daac7fa4777d64e9168610000909bda78fceefda629300c404a4832f172aee27cde7690eb95f0fcdb32409261cc4cd92444b8b58bdbaf0157da42244481688fe9141a2a3c2dbb9f1c6e71fc41287a3adc9d7fac5f19a449776e8635b46e73956e4034262fd0eafb52710366ffc6d91d471a2f2bda11a4710b91673571c85af0df4b4e8d9
# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# http_crypto_func.inc 
# Revision: 1.2
#


#---------------------------------------------------------#
# DES encryption code                                     #
#---------------------------------------------------------#



HTTP_perm1 = make_list (57, 49, 41, 33, 25, 17,  9,
                     1, 58, 50, 42, 34, 26, 18,
                    10,  2, 59, 51, 43, 35, 27,
                    19, 11,  3, 60, 52, 44, 36,
                    63, 55, 47, 39, 31, 23, 15,
                     7, 62, 54, 46, 38, 30, 22,
                    14,  6, 61, 53, 45, 37, 29,
                    21, 13,  5, 28, 20, 12,  4 );


HTTP_perm2 = make_list (14, 17, 11, 24,  1,  5,
                     3, 28, 15,  6, 21, 10,
                    23, 19, 12,  4, 26,  8,
                    16,  7, 27, 20, 13,  2,
                    41, 52, 31, 37, 47, 55,
                    30, 40, 51, 45, 33, 48,
                    44, 49, 39, 56, 34, 53,
                    46, 42, 50, 36, 29, 32 );

HTTP_perm3 = make_list (58, 50, 42, 34, 26, 18, 10,  2,
                    60, 52, 44, 36, 28, 20, 12,  4,
                    62, 54, 46, 38, 30, 22, 14,  6,
                    64, 56, 48, 40, 32, 24, 16,  8,
                    57, 49, 41, 33, 25, 17,  9,  1,
                    59, 51, 43, 35, 27, 19, 11,  3,
                    61, 53, 45, 37, 29, 21, 13,  5,
                    63, 55, 47, 39, 31, 23, 15,  7 );

HTTP_perm4 = make_list (32,  1,  2,  3,  4,  5,
                     4,  5,  6,  7,  8,  9,
                     8,  9, 10, 11, 12, 13,
                    12, 13, 14, 15, 16, 17,
                    16, 17, 18, 19, 20, 21,
                    20, 21, 22, 23, 24, 25,
                    24, 25, 26, 27, 28, 29,
                    28, 29, 30, 31, 32,  1 );

HTTP_perm5 = make_list (16,  7, 20, 21,
                    29, 12, 28, 17,
                     1, 15, 23, 26,
                     5, 18, 31, 10,
                     2,  8, 24, 14,
                    32, 27,  3,  9,
                    19, 13, 30,  6,
                    22, 11,  4, 25 );

HTTP_perm6 = make_list (40,  8, 48, 16, 56, 24, 64, 32,
                    39,  7, 47, 15, 55, 23, 63, 31,
                    38,  6, 46, 14, 54, 22, 62, 30,
                    37,  5, 45, 13, 53, 21, 61, 29,
                    36,  4, 44, 12, 52, 20, 60, 28,
                    35,  3, 43, 11, 51, 19, 59, 27,
                    34,  2, 42, 10, 50, 18, 58, 26,
                    33,  1, 41,  9, 49, 17, 57, 25 );

HTTP_sc = make_list (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1);

HTTP_sbox =    make_list (        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
                              0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
                              4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
                             15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
	                  
                             15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
		              3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
			      0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
			     13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
	                  
                             10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
		             13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
			     13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
			      1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,

	                      7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
		             13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
			     10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
			      3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,

	                      2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
		             14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
			      4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
			     11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,

		             12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
		             10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
			      9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
			      4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,

		              4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
		             13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
			      1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
			      6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,

	                     13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
		              1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
			      7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
			      2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 );

function HTTP_permute (in, p)
{
 local_var buf, i;

 buf = NULL;
 for (i = 0; i < strlen(p); i++)
    buf += in[ord(p[i]) - 1];
 
 return buf;
}

global_var HTTP_b, HTTP_er, HTTP_erk, HTTP_cb, HTTP_pcb, HTTP_l, HTTP_r, HTTP_r2, HTTP_buf;

HTTP_b = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

HTTP_er = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

HTTP_erk = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

HTTP_cb = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

HTTP_pcb = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

HTTP_l = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

HTTP_r = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

HTTP_r2 = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

_HTTP_buf = make_list (
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

function HTTP_des_encrypt (in, key, type)
{
 local_var i, j, k, c, d, cd, pd1, l, r, rl, pk1;
 local_var cb, pcb, r2, tmp, val, ki;
 local_var m, n;
 local_var cmpt, tmp1, tmp2, count;
 
 pk1 = c = d = cd = NULL;

 for (cmpt = 0; cmpt < 56; cmpt++)
   pk1 += key[HTTP_perm1[cmpt] - 1];

 c = substr (pk1, 0, 27);
 d = substr (pk1, 28, 55);

 for (i = 0; i < 16; i++)
 {
  tmp1 = tmp2 = NULL;
  count = HTTP_sc[i];
  for (cmpt = 0; cmpt < 28; cmpt++)
  {
    tmp1 += c[(cmpt+count)%28];
    tmp2 += d[(cmpt+count)%28];
  }

  c = tmp1;
  d = tmp2;

  cd = c + d;

  ki[i] = NULL;
  for (cmpt = 0; cmpt < 48; cmpt++)
    ki[i] += cd[HTTP_perm2[cmpt] - 1];
 }

 for (cmpt = 0; cmpt < 64; cmpt++)
 {
  if (cmpt < 32)
    HTTP_l[cmpt] = in[HTTP_perm3[cmpt] - 1];
  else
    HTTP_r[cmpt-32] = in[HTTP_perm3[cmpt] - 1];
 }

 
 for (i = 0; i < 16; i++)
 {
  for (cmpt = 0; cmpt < 48; cmpt++)
     HTTP_er[cmpt] = HTTP_r[HTTP_perm4[cmpt] - 1];

  if (type == 1)
  { 
    tmp2 = ki[i];
    for (cmpt = 0; cmpt < 48; cmpt++)
      HTTP_b[cmpt] = (HTTP_er[cmpt] ^ ord(tmp2[cmpt]));
  }
  else
  {
    tmp2 = ki[15-i];
    for (cmpt = 0; cmpt < 48; cmpt++)
      HTTP_b[cmpt] = (HTTP_er[cmpt] ^ ord(tmp2[cmpt]));
  }

  for (j = 0; j < 8; j++)
  {
   tmp2 = j*6;
   m = (HTTP_b[tmp2] << 1);
   m = m | (HTTP_b[tmp2 + 5]);

   n = (HTTP_b[tmp2 + 1] << 3);
   n = n | (HTTP_b[tmp2 + 2] << 2);
   n = n | (HTTP_b[tmp2 + 3] << 1);
   n = n | (HTTP_b[tmp2 + 4]);

   tmp1 = HTTP_sbox [j*4*16 + m*16 + n];
   for (k = 0; k < 4; k++)
      if ((tmp1 & (1<<(3-k))) == 0)
        HTTP_b[tmp2 + k] = 0;
      else
        HTTP_b[tmp2 + k] = 1;
  }
 
  for (j=0; j<8; j++)
  {
   tmp2 = j*6;
   tmp1 = j*4;
   HTTP_cb[tmp1] = HTTP_b[tmp2];
   HTTP_cb[tmp1+1] = HTTP_b[tmp2+1];
   HTTP_cb[tmp1+2] = HTTP_b[tmp2+2];
   HTTP_cb[tmp1+3] = HTTP_b[tmp2+3];
  }

  for (cmpt = 0; cmpt < 32; cmpt++)
    HTTP_pcb[cmpt] = HTTP_cb[HTTP_perm5[cmpt] - 1];
 
  for (cmpt = 0; cmpt < 32; cmpt++)
    HTTP_r2[cmpt] = (HTTP_l[cmpt] ^ HTTP_pcb[cmpt]);

  HTTP_l = HTTP_r;
  HTTP_r = HTTP_r2;
 }
 
 for (cmpt = 0; cmpt < 64; cmpt++)
 {
   tmp2 = HTTP_perm6[cmpt]-1;
   if (tmp2 < 32)
     _HTTP_buf[cmpt] = HTTP_r[tmp2];
   else
     _HTTP_buf[cmpt] = HTTP_l[tmp2-32];
 }

 return _HTTP_buf;
}


global_var HTTP_inb;

HTTP_inb = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

function HTTP_set_des_key (key)
{
 local_var keyb, i;

 keyb = NULL;

 for (i=0;i<64;i++)
 {

  if ((ord(key[i/8]) & (1<<(7-(i%8)))) == 0)
    keyb += '\0';
  else
    keyb += '\x01';
 }

 return keyb;
}

function HTTP_str_to_key (str)
{
 local_var key, i;

 key = raw_string ( ((ord(str[0])>>1) << 1) ,
                    ((((ord(str[0])&0x01)<<6) | (ord(str[1])>>2)) << 1) ,
                    ((((ord(str[1])&0x03)<<5) | (ord(str[2])>>3)) << 1) ,
                    ((((ord(str[2])&0x07)<<4) | (ord(str[3])>>4)) << 1) ,
                    ((((ord(str[3])&0x0F)<<3) | (ord(str[4])>>5)) << 1) ,
                    ((((ord(str[4])&0x1F)<<2) | (ord(str[5])>>6)) << 1) ,
                    ((((ord(str[5])&0x3F)<<1) | (ord(str[6])>>7)) << 1) ,
                    ((ord(str[6])&0x7F) << 1) );

 return HTTP_set_des_key(key:key);
}

function HTTP_DES (in, key, _string, type)
{
 local_var inb, keyb, key2, outb, out, buf, i;

 inb = keyb= outb = buf = NULL;;

 if (isnull(_string) || (_string == TRUE))
   key2 = HTTP_str_to_key (str:key);
 else
   key2 = key;

 for (i=0;i<64;i++)
 {
  if ((ord(in[i/8]) & (1<<(7-(i%8)))) == 0)
    HTTP_inb[i] = 0;
  else
    HTTP_inb[i] = 1;    
 }

 outb = HTTP_des_encrypt(in:HTTP_inb, key:key2, type:type);

 out = make_list (0,0,0,0,0,0,0,0);

 for (i=0;i<64;i++) 
 {
  if (outb[i] == 1)
    out[i/8] = out[i/8] | (1<<(7-(i%8)));
 }

 for (i=0;i<8;i++)
 {
  buf += raw_string (out[i]);
 }

 return buf;
}

#---------------------------------------------------------#
# DES-cbc  encryption code                                #
#---------------------------------------------------------#

# Removed!

#---------------------------------------------------------#
# LANMAN2.1 Challenge/Response                            #
#---------------------------------------------------------#

# Removed!


#---------------------------------------------------------#
# NTLM 0.12 Challenge/Response                            #
#---------------------------------------------------------#


function HTTP_NTLM_Hash (password)
{
 if (password)
   return MD4 (password);
 else
   return raw_string(0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0);
}

function HTTP_NTLM_Response (password, hash, challenge)
{
 local_var key1, key2, key3, response;

 response = NULL;

 if (isnull(hash))
   hash = HTTP_NTLM_Hash (password:password);

 response[1] = MD4 (hash);

 hash += raw_string (0x00,0x00,0x00,0x00,0x00);

 key1 = substr (hash, 0, 6);
 key2 = substr (hash, 7, 13);
 key3 = substr (hash, 14, 20);

 response[0] = HTTP_DES (in:challenge, key:key1, type:1) + HTTP_DES (in:challenge, key:key2, type:1) + HTTP_DES (in:challenge, key:key3, type:1);

 return response;
}
