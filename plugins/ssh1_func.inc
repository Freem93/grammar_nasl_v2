#TRUSTED 8cf1947bdd5deb1fe42925998093e241dcd18dca601c3ac1008663357a8b1be5a659b4fee67e7e38342b81eb7ac438ae4768f09e9d54abb5265cf28b3b568c6cc431003ce19560de8fe086a73f680487763fdd8155698fd5a4728326ecf49d031f761002b815712deae62d564809032101faedec597ee940c3074b3007196b621e325f07530c63096470e10510006fdd0a50b513212e3163b990b893a0b6edcfef8c1c8658edfa167b56dd4e41a1bb1d8e89b9779a480e93e56cbd62f30801e3b859d472f465790d1c1dcc6e0439ef895802861808580e7f2f3f7dfc7090ff8cbe22af0bd6d47ed879a8212e7130121a6128dd91ac276d84e0eea5c9edf4ef14f89678918b6df59b90e0118c82eb3f3fedc01198bbac49e100e3d619adf01aa74cf1c20869eb81400226bdaa1732d6bfa6e4859973ae368a8cd2ee3847c09d3b795ce7c936875285dc1195862a1956349b3b8ade7eb7affe383b0ca7de4d10949004fcbec296d563d5755a7e564a0e73f4efea76a493f1f47aae345a6dac16cb5726fff90896e2c566ac4d10c5fd43946652c88a1d2c2eb92b743ad6605bec95ee29e99893827ca214f9e1ee327c1425b9fb54314dc14c635ffbae17f25d50b49ee7e9635cf18b3e24fae609e9380530bf1bcfa92fa1a268e57c6d6cac1fe1b805d54f72b4a259525970866bda9d4535e0d3e432fb756824fd01005cfc050714
#------------------------------------------------------------------------------
# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.11
#


global_var PArray, SBoxes, bf_P, bf_S, NPASS;
global_var bf_enc_iv, bf_dec_iv;
global_var crc32tab, _ssh1_encryption, _ssh1_key, _ssh1_session_id;
global_var _bf_dec_iv, _bf_enc_iv;
global_var _tripledes_dec_iv, _tripledes_enc_iv, _tripledes_key;
global_var cipher_type;

SSH_CIPHER_BLOWFISH = 6;
SSH_CIPHER_3DES = 3;



NPASS = 16;

bf_P = make_list (
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
  0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
  0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
  0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
  0x9216d5d9, 0x8979fb1b
);

bf_S = make_list (
  0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7,
  0xb8e1afed, 0x6a267e96, 0xba7c9045, 0xf12c7f99,
  0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16,
  0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e,
  0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee,
  0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013,
  0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef,
  0x8e79dcb0, 0x603a180e, 0x6c9e0e8b, 0xb01e8a3e,
  0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60,
  0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440,
  0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce,
  0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a,
  0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e,
  0xafd6ba33, 0x6c24cf5c, 0x7a325381, 0x28958677,
  0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193,
  0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032,
  0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88,
  0x23893e81, 0xd396acc5, 0x0f6d6ff3, 0x83f44239,
  0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e,
  0x21c66842, 0xf6e96c9a, 0x670c9c61, 0xabd388f0,
  0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3,
  0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98,
  0xa1f1651d, 0x39af0176, 0x66ca593e, 0x82430e88,
  0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe,
  0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6,
  0x4ed3aa62, 0x363f7706, 0x1bfedf72, 0x429b023d,
  0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b,
  0x075372c9, 0x80991b7b, 0x25d479d8, 0xf6e8def7,
  0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba,
  0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463,
  0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f,
  0x6dfc511f, 0x9b30952c, 0xcc814544, 0xaf5ebd09,
  0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3,
  0xc0cba857, 0x45c8740f, 0xd20b5f39, 0xb9d3fbdb,
  0x5579c0bd, 0x1a60320a, 0xd6a100c6, 0x402c7279,
  0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8,
  0x3c7516df, 0xfd616b15, 0x2f501ec8, 0xad0552ab,
  0x323db5fa, 0xfd238760, 0x53317b48, 0x3e00df82,
  0x9e5c57bb, 0xca6f8ca0, 0x1a87562e, 0xdf1769db,
  0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573,
  0x695b27b0, 0xbbca58c8, 0xe1ffa35d, 0xb8f011a0,
  0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b,
  0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790,
  0xe1ddf2da, 0xa4cb7e33, 0x62fb1341, 0xcee4c6e8,
  0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4,
  0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0,
  0xd08ed1d0, 0xafc725e0, 0x8e3c5b2f, 0x8e7594b7,
  0x8ff6e2fb, 0xf2122b64, 0x8888b812, 0x900df01c,
  0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad,
  0x2f2f2218, 0xbe0e1777, 0xea752dfe, 0x8b021fa1,
  0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299,
  0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9,
  0x165fa266, 0x80957705, 0x93cc7314, 0x211a1477,
  0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf,
  0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49,
  0x00250e2d, 0x2071b35e, 0x226800bb, 0x57b8e0af,
  0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa,
  0x78c14389, 0xd95a537f, 0x207d5ba2, 0x02e5b9c5,
  0x83260376, 0x6295cfa9, 0x11c81968, 0x4e734a41,
  0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915,
  0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400,
  0x08ba6fb5, 0x571be91f, 0xf296ec6b, 0x2a0dd915,
  0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664,
  0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a,
  0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623,
  0xad6ea6b0, 0x49a7df7d, 0x9cee60b8, 0x8fedb266,
  0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1,
  0x193602a5, 0x75094c29, 0xa0591340, 0xe4183a3e,
  0x3f54989a, 0x5b429d65, 0x6b8fe4d6, 0x99f73fd6,
  0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1,
  0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e,
  0x09686b3f, 0x3ebaefc9, 0x3c971814, 0x6b6a70a1,
  0x687f3584, 0x52a0e286, 0xb79c5305, 0xaa500737,
  0x3e07841c, 0x7fdeae5c, 0x8e7d44ec, 0x5716f2b8,
  0xb03ada37, 0xf0500c0d, 0xf01c1f04, 0x0200b3ff,
  0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd,
  0xd19113f9, 0x7ca92ff6, 0x94324773, 0x22f54701,
  0x3ae5e581, 0x37c2dadc, 0xc8b57634, 0x9af3dda7,
  0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41,
  0xe238cd99, 0x3bea0e2f, 0x3280bba1, 0x183eb331,
  0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf,
  0x2cb81290, 0x24977c79, 0x5679b072, 0xbcaf89af,
  0xde9a771f, 0xd9930810, 0xb38bae12, 0xdccf3f2e,
  0x5512721f, 0x2e6b7124, 0x501adde6, 0x9f84cd87,
  0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c,
  0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2,
  0xef1c1847, 0x3215d908, 0xdd433b37, 0x24c2ba16,
  0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd,
  0x71dff89e, 0x10314e55, 0x81ac77d6, 0x5f11199b,
  0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509,
  0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e,
  0x86e34570, 0xeae96fb1, 0x860e5e0a, 0x5a3e2ab3,
  0x771fe71c, 0x4e3d06fa, 0x2965dcb9, 0x99e71d0f,
  0x803e89d6, 0x5266c825, 0x2e4cc978, 0x9c10b36a,
  0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4,
  0xf2f74ea7, 0x361d2b3d, 0x1939260f, 0x19c27960,
  0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66,
  0xe3bc4595, 0xa67bc883, 0xb17f37d1, 0x018cff28,
  0xc332ddef, 0xbe6c5aa5, 0x65582185, 0x68ab9802,
  0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84,
  0x1521b628, 0x29076170, 0xecdd4775, 0x619f1510,
  0x13cca830, 0xeb61bd96, 0x0334fe1e, 0xaa0363cf,
  0xb5735c90, 0x4c70a239, 0xd59e9e0b, 0xcbaade14,
  0xeecc86bc, 0x60622ca7, 0x9cab5cab, 0xb2f3846e,
  0x648b1eaf, 0x19bdf0ca, 0xa02369b9, 0x655abb50,
  0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7,
  0x9b540b19, 0x875fa099, 0x95f7997e, 0x623d7da8,
  0xf837889a, 0x97e32d77, 0x11ed935f, 0x16681281,
  0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99,
  0x57f584a5, 0x1b227263, 0x9b83c3ff, 0x1ac24696,
  0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128,
  0x58ebf2ef, 0x34c6ffea, 0xfe28ed61, 0xee7c3c73,
  0x5d4a14d9, 0xe864b7e3, 0x42105d14, 0x203e13e0,
  0x45eee2b6, 0xa3aaabea, 0xdb6c4f15, 0xfacb4fd0,
  0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105,
  0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250,
  0xcf62a1f2, 0x5b8d2646, 0xfc8883a0, 0xc1c7b6a3,
  0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285,
  0x095bbf00, 0xad19489d, 0x1462b174, 0x23820e00,
  0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061,
  0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb,
  0x7cde3759, 0xcbee7460, 0x4085f2a7, 0xce77326e,
  0xa6078084, 0x19f8509e, 0xe8efd855, 0x61d99735,
  0xa969a7aa, 0xc50c06c2, 0x5a04abfc, 0x800bcadc,
  0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9,
  0xdb73dbd3, 0x105588cd, 0x675fda79, 0xe3674340,
  0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20,
  0x153e21e7, 0x8fb03d4a, 0xe6e39f2b, 0xdb83adf7,
  0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934,
  0x411520f7, 0x7602d4f7, 0xbcf46b2e, 0xd4a20068,
  0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af,
  0x1e39f62e, 0x97244546, 0x14214f74, 0xbf8b8840,
  0x4d95fc1d, 0x96b591af, 0x70f4ddd3, 0x66a02f45,
  0xbfbc09ec, 0x03bd9785, 0x7fac6dd0, 0x31cb8504,
  0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a,
  0x28507825, 0x530429f4, 0x0a2c86da, 0xe9b66dfb,
  0x68dc1462, 0xd7486900, 0x680ec0a4, 0x27a18dee,
  0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6,
  0xaace1e7c, 0xd3375fec, 0xce78a399, 0x406b2a42,
  0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b,
  0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2,
  0x3a6efa74, 0xdd5b4332, 0x6841e7f7, 0xca7820fb,
  0xfb0af54e, 0xd8feb397, 0x454056ac, 0xba489527,
  0x55533a3a, 0x20838d87, 0xfe6ba9b7, 0xd096954b,
  0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33,
  0xa62a4a56, 0x3f3125f9, 0x5ef47e1c, 0x9029317c,
  0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3,
  0x95c11548, 0xe4c66d22, 0x48c1133f, 0xc70f86dc,
  0x07f9c9ee, 0x41041f0f, 0x404779a4, 0x5d886e17,
  0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564,
  0x257b7834, 0x602a9c60, 0xdff8e8a3, 0x1f636c1b,
  0x0e12b4c2, 0x02e1329e, 0xaf664fd1, 0xcad18115,
  0x6b2395e0, 0x333e92e1, 0x3b240b62, 0xeebeb922,
  0x85b2a20e, 0xe6ba0d99, 0xde720c8c, 0x2da2f728,
  0xd0127845, 0x95b794fd, 0x647d0862, 0xe7ccf5f0,
  0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e,
  0x0a476341, 0x992eff74, 0x3a6f6eab, 0xf4f8fd37,
  0xa812dc60, 0xa1ebddf8, 0x991be14c, 0xdb6e6b0d,
  0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804,
  0xf1290dc7, 0xcc00ffa3, 0xb5390f92, 0x690fed0b,
  0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3,
  0xbb132f88, 0x515bad24, 0x7b9479bf, 0x763bd6eb,
  0x37392eb3, 0xcc115979, 0x8026e297, 0xf42e312d,
  0x6842ada7, 0xc66a2b3b, 0x12754ccc, 0x782ef11c,
  0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350,
  0x1a6b1018, 0x11caedfa, 0x3d25bdd8, 0xe2e1c3c9,
  0x44421659, 0x0a121386, 0xd90cec6e, 0xd5abea2a,
  0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe,
  0x9dbc8057, 0xf0f7c086, 0x60787bf8, 0x6003604d,
  0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc,
  0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f,
  0x77a057be, 0xbde8ae24, 0x55464299, 0xbf582e61,
  0x4e58f48f, 0xf2ddfda2, 0xf474ef38, 0x8789bdc2,
  0x5366f9c3, 0xc8b38e74, 0xb475f255, 0x46fcd9b9,
  0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2,
  0x466e598e, 0x20b45770, 0x8cd55591, 0xc902de4c,
  0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e,
  0xb77f19b6, 0xe0a9dc09, 0x662d09a1, 0xc4324633,
  0xe85a1f02, 0x09f0be8c, 0x4a99a025, 0x1d6efe10,
  0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169,
  0xdcb7da83, 0x573906fe, 0xa1e2ce9b, 0x4fcd7f52,
  0x50115e01, 0xa70683fa, 0xa002b5c4, 0x0de6d027,
  0x9af88c27, 0x773f8641, 0xc3604c06, 0x61a806b5,
  0xf0177a28, 0xc0f586e0, 0x006058aa, 0x30dc7d62,
  0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634,
  0xbbcbee56, 0x90bcb6de, 0xebfc7da1, 0xce591d76,
  0x6f05e409, 0x4b7c0188, 0x39720a3d, 0x7c927c24,
  0x86e3725f, 0x724d9db9, 0x1ac15bb4, 0xd39eb8fc,
  0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4,
  0x1e50ef5e, 0xb161e6f8, 0xa28514d9, 0x6c51133c,
  0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837,
  0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0,
  0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b,
  0x5cb0679e, 0x4fa33742, 0xd3822740, 0x99bc9bbe,
  0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b,
  0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4,
  0x5748ab2f, 0xbc946e79, 0xc6a376d2, 0x6549c2c8,
  0x530ff8ee, 0x468dde7d, 0xd5730a1d, 0x4cd04dc6,
  0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304,
  0xa1fad5f0, 0x6a2d519a, 0x63ef8ce2, 0x9a86ee22,
  0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4,
  0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6,
  0x2826a2f9, 0xa73a3ae1, 0x4ba99586, 0xef5562e9,
  0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59,
  0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593,
  0xe990fd5a, 0x9e34d797, 0x2cf0b7d9, 0x022b8b51,
  0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28,
  0x1f9f25cf, 0xadf2b89b, 0x5ad6b472, 0x5a88f54c,
  0xe029ac71, 0xe019a5e6, 0x47b0acfd, 0xed93fa9b,
  0xe8d3c48d, 0x283b57cc, 0xf8d56629, 0x79132e28,
  0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c,
  0x15056dd4, 0x88f46dba, 0x03a16125, 0x0564f0bd,
  0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a,
  0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319,
  0x7533d928, 0xb155fdf5, 0x03563482, 0x8aba3cbb,
  0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f,
  0x4de81751, 0x3830dc8e, 0x379d5862, 0x9320f991,
  0xea7a90c2, 0xfb3e7bce, 0x5121ce64, 0x774fbe32,
  0xa8b6e37e, 0xc3293d46, 0x48de5369, 0x6413e680,
  0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166,
  0xb39a460a, 0x6445c0dd, 0x586cdecf, 0x1c20c8ae,
  0x5bbef7dd, 0x1b588d40, 0xccd2017f, 0x6bb4e3bb,
  0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5,
  0x72eacea8, 0xfa6484bb, 0x8d6612ae, 0xbf3c6f47,
  0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370,
  0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d,
  0x4040cb08, 0x4eb4e2cc, 0x34d2466a, 0x0115af84,
  0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048,
  0x6f3f3b82, 0x3520ab82, 0x011a1d4b, 0x277227f8,
  0x611560b1, 0xe7933fdc, 0xbb3a792b, 0x344525bd,
  0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9,
  0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7,
  0x1a908749, 0xd44fbd9a, 0xd0dadecb, 0xd50ada38,
  0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f,
  0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c,
  0xbf97222c, 0x15e6fc2a, 0x0f91fc71, 0x9b941525,
  0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1,
  0xb6c1075e, 0xe3056a0c, 0x10d25065, 0xcb03a442,
  0xe0ec6e0e, 0x1698db3b, 0x4c98a0be, 0x3278e964,
  0x9f1f9532, 0xe0d392df, 0xd3a0342b, 0x8971f21e,
  0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8,
  0xdf359f8d, 0x9b992f2e, 0xe60b6f47, 0x0fe3f11d,
  0xe54cda54, 0x1edad891, 0xce6279cf, 0xcd3e7e6f,
  0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299,
  0xf523f357, 0xa6327623, 0x93a83531, 0x56cccd02,
  0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc,
  0xde966292, 0x81b949d0, 0x4c50901b, 0x71c65614,
  0xe6c6c7bd, 0x327a140a, 0x45e1d006, 0xc3f27b9a,
  0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6,
  0x71126905, 0xb2040222, 0xb6cbcf7c, 0xcd769c2b,
  0x53113ec0, 0x1640e3d3, 0x38abbd60, 0x2547adf0,
  0xba38209c, 0xf746ce76, 0x77afa1c5, 0x20756060,
  0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e,
  0x1948c25c, 0x02fb8a8c, 0x01c36ae4, 0xd6ebe1f9,
  0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f,
  0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6
);

PArray = make_list (); PArray[17] = 0;
SBoxes = make_list (); Sboxes[4*256 - 1] = 0;

function read_dword (buf, pos)
{
 return ord(buf[pos]) +
        (ord(buf[pos+1]) << 8) +
        (ord(buf[pos+2]) << 16) +
        (ord(buf[pos+3]) << 24) ;
}

function write_dword (dword)
{
 return raw_string (
         dword & 0xFF,
         (dword >> 8) & 0xFF,
         (dword >> 16) & 0xFF,
         (dword >> 24) & 0xFF
        );
}


function S (x, i)
{
 return SBoxes[i * 256 + ((x >>> ((3-i)*8)) & 0xFF)];
}


function bf_F(x)
{
 return ((S(x:x, i:0) + S(x:x, i:1)) ^ S(x:x, i:2)) + S(x:x, i:3);
}


function ROUND (a,b,n)
{
 return a ^ bf_F(x:b) ^ PArray[n];
}


# data - 8 bytes
function blowfish_encipher (data)
{
 local_var Xl, Xr;

 Xl = read_dword (buf:data, pos:0);
 Xr = read_dword (buf:data, pos:4);

 Xl = Xl ^ PArray[0];
 Xr = ROUND (a:Xr, b:Xl, n:1);
 Xl = ROUND (a:Xl, b:Xr, n:2);
 Xr = ROUND (a:Xr, b:Xl, n:3);
 Xl = ROUND (a:Xl, b:Xr, n:4);
 Xr = ROUND (a:Xr, b:Xl, n:5);
 Xl = ROUND (a:Xl, b:Xr, n:6);
 Xr = ROUND (a:Xr, b:Xl, n:7);
 Xl = ROUND (a:Xl, b:Xr, n:8);
 Xr = ROUND (a:Xr, b:Xl, n:9);
 Xl = ROUND (a:Xl, b:Xr, n:10);
 Xr = ROUND (a:Xr, b:Xl, n:11);
 Xl = ROUND (a:Xl, b:Xr, n:12);
 Xr = ROUND (a:Xr, b:Xl, n:13);
 Xl = ROUND (a:Xl, b:Xr, n:14);
 Xr = ROUND (a:Xr, b:Xl, n:15);
 Xl = ROUND (a:Xl, b:Xr, n:16);
 Xr = Xr ^ PArray[17];

 return write_dword (dword:Xr) + write_dword (dword:Xl);
}


# data - 8 bytes
function blowfish_decipher (data)
{
 local_var Xl, Xr;

 Xl = read_dword (buf:data, pos:0);
 Xr = read_dword (buf:data, pos:4);

 Xl = Xl ^ PArray[17];
 Xr = ROUND (a:Xr, b:Xl, n:16);
 Xl = ROUND (a:Xl, b:Xr, n:15);
 Xr = ROUND (a:Xr, b:Xl, n:14);
 Xl = ROUND (a:Xl, b:Xr, n:13);
 Xr = ROUND (a:Xr, b:Xl, n:12);
 Xl = ROUND (a:Xl, b:Xr, n:11);
 Xr = ROUND (a:Xr, b:Xl, n:10);
 Xl = ROUND (a:Xl, b:Xr, n:9);
 Xr = ROUND (a:Xr, b:Xl, n:8);
 Xl = ROUND (a:Xl, b:Xr, n:7);
 Xr = ROUND (a:Xr, b:Xl, n:6);
 Xl = ROUND (a:Xl, b:Xr, n:5);
 Xr = ROUND (a:Xr, b:Xl, n:4);
 Xl = ROUND (a:Xl, b:Xr, n:3);
 Xr = ROUND (a:Xr, b:Xl, n:2);
 Xl = ROUND (a:Xl, b:Xr, n:1);
 Xr = Xr ^ PArray[0];

 return write_dword (dword:Xr) + write_dword (dword:Xl);
}

function tripledes_initialize(key)
{
 local_var i;

 _tripledes_key = _tripledes_enc_iv = _tripledes_key = make_list(); 
 for ( i = 0 ; i < 3 ; i ++ )
 {
  _tripledes_dec_iv[i] =  _tripledes_enc_iv[i] = crap(data:'\0', length:8);
 }
 
 _tripledes_key[0] = substr(key, 0, 7);
 _tripledes_key[1] = substr(key, 8, 15);
 _tripledes_key[2] = substr(key, 16, 23);
}

function blowfish_initialize (key)
{
 local_var i, j, data, keybytes;

 _bf_enc_iv = _bf_dec_iv = crap(data:'\0', length:8);

 keybytes = strlen(key);

 for (i = 0; i < 18; i++)
 {
  PArray[i] = bf_P[i];
 }

 for (i = 0; i < 4; i++)
 {
  for (j = 0; j < 256; j++)
     SBoxes [i*256 + j] = bf_S [i*256 + j];
 }

 j = 0;
 for (i = 0; i < NPASS + 2; ++i)
 {
  data = (ord(key[j]) << 24) +
         (ord(key[(j+1) % keybytes]) << 16) +
         (ord(key[(j+2) % keybytes]) << 8) +
         ord(key[(j+3) % keybytes]) ;
  PArray[i] = PArray[i] ^ data;
  j = (j + 4) % keybytes;
 }

 data = raw_string (0,0,0,0,0,0,0,0);

 for (i = 0; i < NPASS + 2; i += 2)
 {
  data = blowfish_encipher (data:data);
  PArray[i] = read_dword (buf:data, pos:0);
  PArray[i + 1] = read_dword (buf:data, pos:4);
 }

 for (i = 0; i < 4; ++i)
 {
  for (j = 0; j < 256; j += 2)
  {
   data = blowfish_encipher (data:data);
   SBoxes [i*256 + j] = read_dword (buf:data, pos:0);
   SBoxes [i*256 + j + 1] = read_dword (buf:data, pos:4);
  }
 }
}


# data length must be % 8
function blowfish_decrypt (data)
{
 local_var tmp, to_decrypt, i, iv, len, j, dec;

 tmp = NULL;

 iv = _bf_dec_iv;

 len = strlen(data);

 for (i=0; i<len; i+=8)
 {
  to_decrypt = substr (data, i, i+7);

  dec = blowfish_decipher(data:to_decrypt);

  for (j=0; j<8; j++)
    dec[j] = raw_string(ord(dec[j]) ^ ord(iv[j]));

  tmp = tmp + dec;
  iv = to_decrypt;
 }

 _bf_dec_iv = iv;

 return tmp;
}


# data length must be % 8
function blowfish_encrypt (data)
{
 local_var tmp, to_encrypt, i, iv, len, j;

 tmp = NULL;
 iv = _bf_enc_iv;

 len = strlen(data);

 for (i = 0;i < len; i += 8)
 {
  to_encrypt = substr (data, i, i+7);
  for (j=0; j<8; j++)
    to_encrypt[j] = raw_string(ord(to_encrypt[j]) ^ ord(iv[j]));

  iv = blowfish_encipher (data:to_encrypt);

  tmp += iv;
 }

 _bf_enc_iv = iv;

 return tmp;
}


function tripledes_encrypt(data)
{
 data = des_cbc_encrypt2(data:data, key:_tripledes_key[0], iv:_tripledes_enc_iv[0]);
 _tripledes_enc_iv[0] = data[1];

 data = des_cbc_decrypt2(data:data[0], key:_tripledes_key[1], iv:_tripledes_enc_iv[1]);
 _tripledes_enc_iv[1] = data[1];

 data = des_cbc_encrypt2(data:data[0], key:_tripledes_key[2], iv:_tripledes_enc_iv[2]);
 _tripledes_enc_iv[2] = data[1];

 data = data[0];
 return data;
}

function tripledes_decrypt(data)
{
 local_var p;

 data = des_cbc_decrypt2(data:data, key:_tripledes_key[2], iv:_tripledes_dec_iv[2]);
 _tripledes_dec_iv[2] = data[1];
 
 data = des_cbc_encrypt2(data:data[0], key:_tripledes_key[1], iv:_tripledes_dec_iv[1]);
 _tripledes_dec_iv[1] = data[1];

 data = des_cbc_decrypt2(data:data[0], key:_tripledes_key[0], iv:_tripledes_dec_iv[0]);
 _tripledes_dec_iv[0] = data[1];

 data = data[0];

 return data;
}


function des_cbc_encrypt2(data, key, iv)
{
 local_var l, len, j, tmp, to_encrypt;

 len = strlen(data);
 tmp = NULL;

 for(l=0; l<len; l+=8)
 {
  to_encrypt = substr(data, l, l+7);

  for (j=0; j<8; j++)
    to_encrypt[j] = raw_string(ord(to_encrypt[j]) ^ ord(iv[j]));

  iv = DES (in:to_encrypt, key:set_des_key(key:key), _string:FALSE, type:1);

  tmp += iv;
 }

 return make_list(tmp, iv);
}


function des_cbc_decrypt2(data, key, iv)
{
 local_var l, len, j, tmp, dec, to_decrypt;

 len = strlen(data);
 tmp = NULL;

 for(l=0; l<len; l+=8)
 {
  to_decrypt = substr(data, l, l+7);

  dec = DES (in:to_decrypt, key:set_des_key(key:key), _string:FALSE, type:0);
  for (j=0; j<8; j++)
    dec[j] = raw_string(ord(dec[j]) ^ ord(iv[j]));

  iv = to_decrypt;

  tmp += dec;
 }

 return make_list(tmp, iv);
}


crc32tab = make_list(
  0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
  0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
  0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
  0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
  0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
  0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
  0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
  0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
  0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
  0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
  0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
  0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
  0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
  0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
  0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
  0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
  0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
  0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
  0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
  0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
  0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
  0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
  0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
  0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
  0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
  0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
  0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
  0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
  0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
  0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
  0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
  0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
  0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
  0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
  0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
  0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
  0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
  0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
  0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
  0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
  0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
  0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
  0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
  0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
  0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
  0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
  0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
  0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
  0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
  0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
  0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
  0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
  0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
  0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
  0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
  0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
  0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
  0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
  0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
  0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
  0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
  0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
  0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
  0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
);


function crc32(data)
{
 local_var crc, i, len;

 len = strlen(data);

 crc = 0;

 for (i=0; i<len; i++)
    crc = (crc >>> 8) ^ crc32tab[((crc & 0xff) ^ ord(data[i]))];

 return crc;
}


function ssh1_recv(timeout)
{
 local_var header, len, payload, plen, padding, crc, data, null_pkt;

 null_pkt = raw_int8(i:0);

 header = recv(socket:_ssh_socket, length:4, min:4, timeout:timeout);
 if (strlen(header) < 4) return null_pkt;

 len = ntol (buffer:header, begin:0);
 if ((len == 0) || (len > max_packet_size)) return null_pkt;

 plen = 8 - ((len)%8);

 padding = recv(socket:_ssh_socket, length:plen, min:plen, timeout:timeout);
 if(strlen(padding) < plen ) return null_pkt;
 
 payload = recv(socket:_ssh_socket, length:len, min:len, timeout:timeout);
 if (strlen(payload) < len) return null_pkt;

 if (_ssh1_encryption)
 {
  data = padding+payload;

  if ( cipher_type == SSH_CIPHER_BLOWFISH )
   payload = blowfish_decrypt(data:data);
  else if ( cipher_type == SSH_CIPHER_3DES )
   payload = tripledes_decrypt(data:data);
  padding = substr(payload, 0, plen-1);
  payload = substr(payload, plen, strlen(payload)-1);
 }

 len = strlen(payload);
 crc = ntol(buffer:payload, begin:len-4);
 payload = substr(payload, 0, len-5);

 if (crc != crc32(data:padding+payload))
   return null_pkt;

 # SSH_MSG_DEBUG
 if (ord(payload[0]) == 36)
   return ssh1_recv(timeout:timeout);

 return payload;
}


function ssh1_send(payload, code)
{
 local_var crc, data, len, plen;

 data = raw_int8(i:code) + payload;

 len = strlen(data) + 4;
 plen = 8 - ((len)%8);

 data = crap(data:'\0', length:plen) + data;
 data = data + raw_int32(i:crc32(data:data));

 if (_ssh1_encryption)
 {
   if ( cipher_type == SSH_CIPHER_BLOWFISH )
    data = blowfish_encrypt(data:data);
   else if ( cipher_type == SSH_CIPHER_3DES )
    data = tripledes_encrypt(data:data);
 }

 data = raw_int32(i:len) + data;

 send(socket:_ssh_socket, data:data);
}


function raw_int16(i)
{
 local_var buf;

 buf = raw_string (
        (i>>8) & 255,
        (i) & 255
		 );
 return buf;
}


function ntos(buffer,pos)
{
 local_var len;

 len = ord(buffer[pos])*256 +
       ord(buffer[pos+1]);

 return len;
}


function get_bignum1(buffer, pos)
{
 local_var len, bits;

 bits = ntos(buffer:buffer, pos:pos);
 len = (bits + 7) / 8;

 return substr(buffer, pos+2, pos+2+len-1);
}


function putbignum1(buffer)
{
 local_var len;

 len = strlen(buffer) * 8;
 return raw_int16(i:len) + buffer;
}


function len_long()
{
 return 4;
}


function len_bn(bn)
{
 return 2 + strlen(bn);
}


RSA1_KEY_ID = 'SSH PRIVATE KEY FILE FORMAT 1.1\n\0';

function parse_private_key(data, passphrase)
{
 local_var len, key, pos, e, n, d, comment;
 local_var id_len, cipher, reserved, klen;
 local_var id, bits;

 pos = 0;
 len = strlen(data);
 id_len = strlen(RSA1_KEY_ID);

 if ( len < (id_len+9))
   return NULL;

 id = substr(data, 0, id_len-1);
 if (id >!< RSA1_KEY_ID)
   return NULL;

 cipher = ord(data[id_len]);
 if (cipher != 0 && cipher != 3)
 {
   set_ssh_error(msg:string("Unsupported cipher in private key: ", cipher));
   return NULL;
 }

 reserved = ntol(buffer:data, begin:id_len+1);
 klen = ntol(buffer:data, begin:id_len+5);

 pos = id_len + 9;

 # parse n
 n = get_bignum1(buffer:data, pos:pos);
 pos += strlen(n) + 2;

 # parse e
 e = get_bignum1(buffer:data, pos:pos);
 pos += strlen(e) + 2;

 comment = getstring(buffer:data, pos:pos);
 pos += 4 + strlen(comment);

 data = substr(data, pos, len-1);

 # 3des
 if (cipher == 3)
 {
  passphrase = MD5(passphrase);
  passphrase = passphrase + substr(passphrase, 0, 7);

  data = des_cbc_decrypt2(data:data, key:substr(passphrase, 0, 7), iv:'\0\0\0\0\0\0\0\0');
  data = des_cbc_encrypt2(data:data[0], key:substr(passphrase, 8, 15), iv:'\0\0\0\0\0\0\0\0');
  data = des_cbc_decrypt2(data:data[0], key:substr(passphrase, 16, 23), iv:'\0\0\0\0\0\0\0\0');
  data = data[0];
 }

 if (ntos(buffer:data, pos:0) != ntos(buffer:data, pos:2))
   return NULL;

 d = get_bignum1(buffer:data, pos:4);

 return make_list(e,n,d);
}



function ssh_kex1(nofingerprint)
{
 local_var payload, cookie, pos;
 local_var skey_bits, skey_e, skey_n;
 local_var hkey_bits, hkey_e, hkey_n;
 local_var cflags, ciphers, auth;
 local_var sflags, i, id;
 local_var session, enc, cipher;
 local_var fkey, fe, fn;

 _ssh1_encryption = FALSE;

 payload = ssh1_recv();
 if (ord(payload[0]) != 2)
 {
   set_ssh_error(msg:string("Received code was not SSH_SMSG_PUBLIC_KEY (2). It was : ", ord(payload[0])));
   return -1;
 }

 cookie = substr(payload,1,8);
 
 pos = 9;

 # server key
 skey_bits = ntol(buffer:payload, begin:pos);
 pos += len_long();
 skey_e = get_bignum1(buffer:payload, pos:pos);
 pos += len_bn(bn:skey_e);
 skey_n = get_bignum1(buffer:payload, pos:pos);
 pos += len_bn(bn:skey_n);

 # host key
 hkey_bits = ntol(buffer:payload, begin:pos);
 pos += len_long();
 hkey_e = get_bignum1(buffer:payload, pos:pos);
 pos += len_bn(bn:hkey_e);
 hkey_n = get_bignum1(buffer:payload, pos:pos);
 pos += len_bn(bn:hkey_n);

 if (isnull(nofingerprint) || nofingerprint == FALSE)
 {
  fkey = get_kb_item("SSH/KnownFingerprint/ssh-rsa1");
  if (fkey)
  {
   fkey = split(fkey, sep:'|', keep:FALSE);
   fe = bn_raw2dec(hkey_e);
   fn = bn_raw2dec(hkey_n);
   if (fe != fkey[0] || fn != fkey[1])
   {
    set_ssh_error(msg:"Server public key does not match the known host fingerprint");
    return -1;
   }
  }
 }

 sflags = ntol(buffer:payload, begin:pos);
 pos += len_long();
 ciphers = ntol(buffer:payload, begin:pos);
 pos += len_long();
 auth = ntol(buffer:payload, begin:pos);

 # detect blowfish or 3des
 if (ciphers & ( 1 << 6 ) )
 {
   cipher_type = SSH_CIPHER_BLOWFISH;
 }
 else if ( ciphers & ( 1 << 3 ) )
 {
   cipher_type = SSH_CIPHER_3DES;
 }
 else
 {
   set_ssh_error(msg:string("The remote SSH server does not support blowfish nor 3des encryption."));
   return -1;
 }

 id = MD5(hkey_n + skey_n + cookie);
 _ssh1_session_id = id;

 session = bn_random(need:(32*8));
 if (strlen(session) > 32)
   session = substr(session, 0, 31);

 _ssh1_key = session;
 if ( cipher_type == SSH_CIPHER_BLOWFISH )
  blowfish_initialize (key:_ssh1_key);
 else if ( cipher_type == SSH_CIPHER_3DES )
  tripledes_initialize(key:_ssh1_key);

 for (i=0; i<16; i++)
   session[i] = raw_string(ord(session[i]) ^ ord(id[i]));

 if (bn_cmp(key1:skey_n, key2:hkey_n) <= 0)
 {
  enc = rsa_public_encrypt(data:session, e:skey_e, n:skey_n);
  enc = rsa_public_encrypt(data:enc, e:hkey_e, n:hkey_n);
 }
 else
 {
  enc = rsa_public_encrypt(data:session, e:hkey_e, n:hkey_n);
  enc = rsa_public_encrypt(data:enc, e:skey_e, n:skey_n);
 }

 cipher = cipher_type; 
 cflags = 0;

 payload = raw_int8(i:cipher) + cookie + putbignum1(buffer:enc) + raw_int32(i:cflags);

 ssh1_send(payload:payload, code:3);

 _ssh1_encryption = TRUE;

 payload = ssh1_recv();
 if (ord(payload[0]) != 14)
 {
   set_ssh_error(msg:string("Received code was not SSH_SMSG_SUCCESS (14). It was : ", ord(payload[0])));
   return -1;
 }

 return 0;
}



function ssh_userauth1(login, password, priv, passphrase)
{
 local_var payload, rsa, challenge, dec, hash;

 payload = putstring(buffer:login);

 # SSH_CMSG_USER
 ssh1_send( payload:payload, code:4);

 payload = ssh1_recv();
 if (ord(payload[0]) != 15)
 {
   set_ssh_error(msg:string("Received code was not SSH_SMSG_FAILURE (15). It was : ", ord(payload[0])));
   return -1;
 }

 if (!isnull(priv))
 {
  rsa = parse_private_key(data:priv, passphrase:passphrase);
  if (isnull(rsa))
  {
   set_ssh_error(msg:string("Invalid RSA1 private key!"));
   return -1;
  }

  payload = putbignum1(buffer:rsa[1]);

  # SSH_CMSG_AUTH_RSA
  ssh1_send(payload:payload, code:6);

  payload = ssh1_recv();
  if (ord(payload[0]) != 7)
  {
   set_ssh_error(msg:string("Received code was not SSH_SMSG_AUTH_RSA_CHALLENGE (7). It was : ", ord(payload[0])));
   return -1;
  }

  challenge = get_bignum1(buffer:payload, pos:1);
  dec = rsa_private_decrypt(e:rsa[0], n:rsa[1], d:rsa[2], sig:challenge);
  hash = MD5(dec + _ssh1_session_id);

  payload = hash;

  # SSH_CMSG_AUTH_RSA_RESPONSE
  ssh1_send(payload:payload, code:8);

  payload = ssh1_recv();
  if (ord(payload[0]) != 14)
  {
   set_ssh_error(msg:string("Received code was not SSH_SMSG_SUCCESS (14). It was : ", ord(payload[0])));
   return -1;
  }
 }
 else
 {
  payload = putstring(buffer:password);

  # SSH_CMSG_AUTH_PASSWORD
  ssh1_send(payload:payload, code:9);

  payload = ssh1_recv();
  if (ord(payload[0]) != 14)
  {
   set_ssh_error(msg:string("Received code was not SSH_SMSG_SUCCESS (14). It was : ", ord(payload[0])));
   return -1;
  }
 }

 return 0;
}


function ssh_cmd1(cmd, timeout, su, supass, dbegin, dend, derror, sent_dbegin, noexec, cisco, enable_pass)
{
 local_var payload, ret, code, spass, tempbuf, ltempbuf, does_echo, last, last5;
 local_var cmdd, sub1, sub2, su_sudo_pass;
 local_var iter, line, cmd_prompt, pagination_prompt, used_exec, val;

 if (_ssh_ltype == 1)
 {
  ssh_close_connection();
  ret = ssh_open_connection();
  if (ret <= 0)
  {
   set_ssh_error(msg:string("SSH_CMD1: can not open a new socket"));
   return NULL;
  }
 }

 does_echo = 0;

 used_exec = 0;
 if (!cisco && !noexec && (isnull(su) || su == SU_NONE))
 {
  payload = putstring(buffer:cmd);

  # SSH_CMSG_EXEC_CMD
  ssh1_send(payload:payload, code:13);

  used_exec = 1;
 }
 else
 {
  payload = putstring(buffer:"vt100") + raw_int32(i:80) + raw_int32(i:24) + raw_int32(i:640) + raw_int32(i:480) + 
            raw_int8(i:193) + raw_int32(i:33000) + 
	    raw_int8(i:192) + raw_int32(i:33000) + 
	    raw_int8(i:0);

  # SSH_CMSG_REQUEST_PTY
  ssh1_send(payload:payload, code:10);

  payload = ssh1_recv();
  if (ord(payload[0]) != 14)
  {
   set_ssh_error(msg:string("Received code was not SSH_SMSG_SUCCESS (14). It was : ", ord(payload[0])));
   return NULL;
  }

  # SSH_CMSG_EXEC_SHELL
  ssh1_send(payload:NULL, code:12);

  spass = 0;
  su_sudo_pass = 0;
 }

 payload = ssh1_recv(timeout:timeout);
 code = ord(payload[0]);

 ret = NULL;

 # SSH_SMSG_STDOUT_DATA && SSH_SMSG_STDERR_DATA
 iter = 0;
 while (code == 17 || code == 18)
 {
  tempbuf = NULL;

  # nb: arbitrary limit to avoid an infinite loop.
  if (strlen(ret) == 0 && ++iter > 100) break;

  if (
    code == 17 || 
    # nb: at least for Red Hat 4 and Solaris, normal command output is
    #     returned as stderr when using exec.
    (code == 18 && used_exec)
  )
  {
   tempbuf = getstring (buffer:payload, pos:1);
   # Strip out escape sequences that might obscure the prompt; eg,
   #   0x00:  1B 5B 30 31 3B 33 32 6D 6E 65 73 73 75 73 40 65    .[01;32mnessus@e
   #   0x10:  78 61 6D 70 6C 65 2E 63 6F 6D 1B 5B 30 31 3B 33    xample.com.[01;3
   #   0x20:  34 6D 20 7E 20 24 1B 5B 30 30 6D 20                4m ~ $.[00m 
   tempbuf = ereg_replace(pattern:'\x1b\\[[0-9]+(;[0-9]+)?[A-Za-z]', replace:'', string:tempbuf);
   tempbuf = ereg_replace(pattern:'\x1b\\[\\?[0-9]+[A-Za-z]', replace:'', string:tempbuf);
   tempbuf = ereg_replace(pattern:'\x1b[0-9]*E', replace:'\n', string:tempbuf);

   if (!used_exec && strlen(ret) == 0)
   {
     # nb: Red Hat 4 echoes back a modified version of the command that
     #     otherwise would not be removed from the command output.
     tempbuf = ereg_replace(pattern:'^([^\r\n]+) \r', replace:"\1", string:tempbuf);
   }

   ret += tempbuf;

   if ( sent_dbegin >< ret ) does_echo = 1;

  if (cisco)
  {
    if (strlen(tempbuf) > 0) last = tempbuf[strlen(tempbuf) - 1];
    else last = NULL;
    if (last == " " && strlen(tempbuf) > 1) last = tempbuf[strlen(tempbuf) - 2];

    if (
      spass == 0 &&
      (
        last == "#" ||
        (last == ">" && strlen(enable_pass) == 0)
      )
    ) spass = 2;
  
    if (spass == 0 && last == ">" && strlen(enable_pass) > 0)
    {
      payload = putstring(buffer:'enable\n');
      # SSH_MSG_STDIN_DATA
      ssh1_send(payload:payload, code:16);  
      spass = 1;
    }
    else if (
      spass == 2 &&
      (
        last == "#" ||
        (last == ">" && strlen(enable_pass) == 0)
      )
    )
    {
      payload = putstring(buffer:cmd);
      # SSH_MSG_STDIN_DATA
      ssh1_send(payload:payload, code:16);  

      timeout += 15;
      spass = 4;

      tempbuf = "";
    }
    else if (
      spass > 0 && spass <= 3 && 
      strlen(enable_pass) && is_password_prompt(tempbuf)
    )
    {
      if (spass >= 3)
      {
        _ssh_cmd_error = 'The provided Cisco \'enable\' password does not appear to be correct.';
        return NULL;
      }

      payload = putstring(buffer:enable_pass+'\n');
      # SSH_MSG_STDIN_DATA
      ssh1_send(payload:payload, code:16);  

      spass++;
    }
    else if (spass == 4)
    {
      ltempbuf = tolower(tempbuf);
      if ( "--more--" >< ltempbuf || "<--- more --->" >< ltempbuf  )
      {
        ssh1_send(payload:putstring(buffer:' '), code:16);  
      }
      else if (last == '#' || last == '>') break;
    }
  }
  else
  {
    if ( strlen(tempbuf) > 5 ) last5 = substr(tempbuf, strlen(tempbuf) - 6, strlen(tempbuf) - 1 );
    else last5 = tempbuf;

    if (spass == 0 && "Press any key to continue" >< tempbuf)
    {
      replace_kb_item(name:"/tmp/ssh_cmd/initial_page", value:tempbuf);

      ssh1_send(payload:putstring(buffer:' '), code:16);  

      ret = tempbuf = "";
    }
    else if (spass == 0 && ("$" >< last5 || "#" >< last5 || ">" >< last5 || "%" >< last5))
    {
      if (isnull(su))
      {
        foreach line (split(tempbuf))
        {
          # empty
        }
        cmd_prompt = line;
        replace_kb_item(name:"/tmp/ssh_cmd/cmd_prompt", value:cmd_prompt);

        payload = putstring(buffer:cmd+'\n');
        # SSH_MSG_STDIN_DATA
        ssh1_send(payload:payload, code:16);  
        
        spass = 4;
        
        ret = tempbuf = "";
      }
      else
      {
        for ( sub1 = 0 ; sub1 < strlen(cmd) ; sub1 += 1024 )
        {
          if ( strlen(cmd) <= sub1 + 1023 ) sub2 = strlen(cmd) - 1;
          else sub2 = sub1 + 1023;
          cmdd = substr(cmd, sub1, sub2);
          payload = putstring(buffer:cmdd);
          # SSH_MSG_STDIN_DATA
          ssh1_send(payload:payload, code:16);  
        }
        spass = 1;
      }
    }
    else if (isnull(su) && spass == 4)
    {
      ltempbuf = tolower(tempbuf);
      if ("-- more --" >< ltempbuf || "next page: space" >< ltempbuf)
      {
        foreach line (split(tempbuf))
        {
          # empty
        }
        pagination_prompt = line;
        ssh1_send(payload:putstring(buffer:' '), code:16);  
      }
      else if ("$" >< last5 || "#" >< last5 || ">" >< last5 || "%" >< last5) break;
    }

    # End of su/sudo command
    if (!isnull(su) && (dend >< tempbuf || derror >< tempbuf))
    {
     if ( su == SU_SU && spass < 2)
       ret = NULL;
     else
       break;
    }

    # su/sudo: set password if needed
    if ( "password:" >< tolower(tempbuf) && strlen(tempbuf) > 0 && tempbuf[strlen(tempbuf) - 1] != '\n' )
     {
      if (  su == SU_SU_AND_SUDO && spass == 1 && su_sudo_pass < 2 )
      {
       payload = putstring(buffer:string(supass, '\n'));
       ssh1_send(payload:payload, code:16);  
       su_sudo_pass ++;
       if ( su_sudo_pass == 2 ) spass = 2;
       }
       else if ( ! isnull(supass) && spass == 1 )
       {
        payload = putstring(buffer:string(supass, '\n'));
        ssh1_send(payload:payload, code:16);  
        spass = 2;
       }
       else if ( isnull(supass) || spass >= 2 ) # Password failed 
       {
        ssh_close_channel(end:0);
        return NULL;
       }
     }
    }
  
    payload = ssh1_recv(timeout:timeout);
    code = ord(payload[0]);
  }
 }

 if (cisco && strlen(ret))
 {
   # remove the command, which Cisco echoes back along with a CR/NL.
   ret = substr(ret, strlen(cmd)+2);

   # remove the final prompt.
   ret = ereg_replace(pattern:'[\r\n]+[^\r\n]+[>#] *$', replace:"", string:ret);

   # remove pagination.
   ret = ereg_replace(pattern:'\r\n (--More--|<--- More --->) \x08+ +\x08+', replace:'\r\n', string:ret);
   ret = str_replace(find:'\x1b\x5b7m--More--\x1b\x5bm\x0d\x21\x1b\x5b\x4b\n', replace:'\r\n', string:ret);
 }

 if (isnull(su))
 {
   if (ret)
   {
     # nb: from an HP ProCurve switch when running a command 
     #     directly rather than through a shell.
     if (
       stridx(ret, "SSH command execution is not supported.") == 0 ||
       stridx(ret, "% Unrecognized command found at '^' position") >= 0
     )
     {
       _ssh_cmd_error = strcat(_ssh_cmd_error, chomp(ret));
       return NULL;
     }
     # nb: from a Juniper router running Junos.
     else if (stridx(ret, "error: syntax error, expecting <command>: -c") >= 0)
     {
       _ssh_cmd_error = strcat(_ssh_cmd_error, chomp(ret));
       return NULL;
     }
     else if (noexec)
     {
       if (stridx(ret, cmd+'\n') == 0) ret = ret - (cmd+'\n');
       else if (stridx(ret, cmd+' \n') == 0) ret = ret - (cmd+' \n');
       else if (stridx(ret, cmd+'\r\n') == 0) ret = ret - (cmd+'\r\n');
       else if (stridx(ret, cmd+' \r\n') == 0) ret = ret - (cmd+' \r\n');
       if (cmd_prompt && cmd_prompt >< ret)
       {
         val = stridx(ret, cmd_prompt);
         if (val == strlen(ret) - strlen(cmd_prompt)) ret = substr(ret, 0, val-1);
       }
       if (pagination_prompt && pagination_prompt >< ret)
       {
         tempbuf = "";
         foreach line (split(ret))
         {
           if (stridx(line, pagination_prompt) != 0) tempbuf += line;
         }
         ret = tempbuf;
       }
       ret = chomp(ret);
     }
   }
 }

 if (!isnull(su))
 { 
  if (derror >< ret) 
  {
    # Try to capture the error message.
    foreach line (split(ret, keep:TRUE))
    {
      if (
        (
          (su == SU_SUDO || su == SU_SU_AND_SUDO) &&
          "is not in the sudoers file" >< line
        ) ||
        (
          (su == SU_SU || su == SU_SU_AND_SUDO) &&
          "su: Authentication failure" >< line
        ) ||
        (
          (su == SU_SUDO || su == SU_SU_AND_SUDO || su == SU_DZDO) &&
          (
            "Sorry, user" >< line ||
            "sorry, you are not allowed to set" >< line
          )
        )
      )
      {
        if (su == SU_DZDO)
        {
          if ("Sorry, user" >< line) line = strstr(line, "Sorry, user");
          if ("sorry, you are not allowed to set" >< line) line = strstr(line, "sorry, you are not allowed to set");
        }
        _ssh_cmd_error = strcat(_ssh_cmd_error, line);
      }
    }
    if (_ssh_cmd_error) _ssh_cmd_error = chomp(_ssh_cmd_error);

    return NULL;
  }
  if (dbegin >!< ret || dend >!< ret) return NULL;
  if (dbegin >< ret)
    ret = substr(strstr(ret, dbegin), strlen(dbegin), strlen(ret)-1);
  if (dend >< ret)
  {
   # sun ssh echoes output even if the option is disabled
   if (does_echo)
    {
     ret = substr(ret, 2, stridx(ret, dend)-1);
    }
   
   else
     ret = substr(ret, 1, stridx(ret, dend)-1);
  }
 }


 return ret;
}

