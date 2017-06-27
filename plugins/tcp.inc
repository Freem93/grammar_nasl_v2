#TRUSTED 3b42f120fd4abe33c2900d68be7f6cf9045b800d2521d3f18efadc8ea59e75c9366d16f63dc4a9711bf4472bf965e1c8f3b9d7b2f78209b3efdcab8c2cbae9b5ecbd0db8f83133b81edb43503a9f88e933fecf41072725e104c7bf687712d16bf8dd4a0c77673e4e42acce126ef1ebc0a835daf651773fbeeb71fc18d0f8acf86ead618675333d9b4cc4b6149728fb03ff7465eb0b60b188d4589c4498cc7f907e6886b07297efc4cf20d0babf14ca9fa2f9a849226f6131148f94b5b5466d6d95af0f18b6ec6debb364511f3a1158bf91a8d55c19838659bcff7f4b56c4dc20f73d8e228b7526d586cd96879e034492f20eefa8556874ade08372d7b8077948070fe42b3b12623eb385877c184c19808e046abdbea99ab54475e26b485f16962deeebcf8485e9b7d585164210df18df39818562a30ec7a0be583a4c684adc0ca62cbc4ae0e93ddfe6fa9305cc5b6ffe35b89d018fb74c58663c981d126f10a2ed0048e113fa9a9a3c47ffb2f25b53d461e2743416842526a4f258ec4c4c8335f39f87a2384d33db7fcb13a0b30e1465e7bd99f770f275ccb3da40ccbbfd0d8a1c3526e12c04b9949c7d82fb92257005e4e67b1930f16e9fd1c2265cd74aa8dca1ca130c92a11738791caae7adeb8b05b824fa7300e1114152ec790c0f03e379d3af7011223044401a1ab9bf67ca8efa1bdb1a79e9bd8d7ed79751e006f740e4
#
# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
#


#-------------------------------------------------------------------------#
# TCP                                                                     #
#-------------------------------------------------------------------------#

tcp_sizes = make_array(
		"th_sport",	16,
		"th_dport", 	16,
		"th_seq",	32,
		"th_ack",	32,
		"th_off",	 4,
		"th_x2",	 4,
		"th_flags",	 8,
		"th_win",	16,
		"th_sum",	16,
		"th_urp",	16);

tcp_struct = make_list(
		"th_sport",
		"th_dport",
		"th_seq",
		"th_ack",
		"th_off",
		"th_x2",
		"th_flags",
		"th_win",
		"th_sum",
		"th_urp",
		"options");


function tcp_checksum(tcp, ip, payload)
{
 local_var src, dst, pseudo, tcp_r;

 if ( (ip["type"] != "ip" && ip["type"] != "ip6") || tcp["type"] != "tcp" )
	{
	display("tcp_checksum: Bad IP argument\n");
	return NULL;
	}

 tcp_r = mktcp(tcp);
 if ( ip["type"] == "ip") 
 {
  ip = ip["data"];
  src = ipaddr(ip["ip_src"]);
  dst = ipaddr(ip["ip_dst"]);
  pseudo = src +
	  dst +
	  mkbyte(0) +
	  mkbyte(IPPROTO_TCP) +
	  mkword(strlen(tcp_r) + strlen(payload)) + tcp_r + payload + crap(data:'\0', length:strlen(payload) % 4);
 }
 else if ( ip["type"] == "ip6" )
 {
  ip = ip["data"];
  pseudo = ip["ip6_src"] + 		
           ip["ip6_dst"] + 		
           '\0\0' + 			
           mkword(strlen(tcp_r)) + 	
           '\0\0\0' + 			
           mkbyte(IPPROTO_TCP) +    
           tcp_r +
           payload;

 }

 
 return inet_sum(pseudo);
}


function tcp_set(tcp, th_sport, th_dport, th_seq, th_ack, th_off, th_x2, th_flags, th_win, th_sum, th_urp )
{
 local_var head, tail, ret, t;

 if ( isnull(tcp) )
 {
  display("set_tcp: NULL TCP packet\n");
  return NULL;
 }

 if ( tcp["type"] != "tcp" )
  {
	display("set_tcp: bad packet type\n");
	return tcp;
	}

 tcp = tcp["data"];

 if ( ! isnull(th_sport) ) tcp["th_sport"] = th_sport;
 if ( ! isnull(th_dport) ) tcp["th_dport"] = th_dport;
 if ( ! isnull(th_seq)   ) tcp["th_seq"]   = th_seq;
 if ( ! isnull(th_ack)   ) tcp["th_ack"]   = th_ack;
 if ( ! isnull(th_off)   ) tcp["th_off"]   = th_off;
 if ( ! isnull(th_x2)    ) tcp["th_x2"]    = th_x2;
 if ( ! isnull(th_flags) ) tcp["th_flags"] = th_flags;
 if ( ! isnull(th_win) )   tcp["th_win"]   = th_win;
 if ( ! isnull(th_sum) )   tcp["th_sum"]   = th_sum;
 if ( ! isnull(th_urp) )   tcp["th_urp"]   = th_urp;

 ret["type"] = "tcp";
 ret["data"] = tcp;

 return ret;
}


function tcp(th_sport, th_dport, th_seq, th_ack, th_off, th_x2, th_flags, th_win, th_sum, th_urp )
{
 local_var empty;
 if ( isnull(th_sport) ) th_sport = rand() % ( 65535  - 1024 ) + 1024;
 if ( isnull(th_dport) ) th_dport = 80;
 if ( isnull(th_seq) ) th_seq = rand() % 0x7fffffff;
 if ( isnull(th_ack) ) th_ack = 0;
 if ( isnull(th_off) ) th_off = 5;
 if ( isnull(th_x2) )  th_x2  = 0;
 if ( isnull(th_flags))th_flags = TH_SYN;
 if ( isnull(th_win) ) th_win  = 65535;
 if ( isnull(th_urp) ) th_urp  = 0;

 empty["type"] = "tcp";
 empty["data"] = NULL;
 
 return tcp_set(tcp:empty,
	 	th_sport:th_sport,
		th_dport:th_dport,
		th_seq:th_seq,
		th_ack:th_ack,
		th_off:th_off,
		th_x2:th_x2,
		th_flags:th_flags,
		th_win:th_win,
		th_sum:th_sum,
		th_urp:th_urp);
}


function tcp_get(tcp, element)
{
 if ( isnull(tcp) || tcp["type"] != "tcp") 
 {
  display("tcp_get: Bad packet type - ", tcp["type"], "\n");
  return NULL;
 }

 tcp = tcp["data"];
 return tcp[element];
}

function mktcp()
{
 local_var tcp, ret, item,n,b;

 tcp = _FCT_ANON_ARGS[0];
 if ( tcp["type"] != "tcp" )
 {
  display("mktcp(): Bad packet type - ", tcp["type"], "\n");
  return NULL;
 }

 tcp = tcp["data"];
 foreach item ( tcp_struct )
 {
  if ( tcp_sizes[item] == 4 ) 
  {
	if ( n == 0 )
	{
	  b = tcp[item];
	  n = 1;
	}
	else 
	{
	  b = b << 4 | tcp[item];
	  ret += mkbyte(b);
	  n = 0;
	}
  }
  else if ( tcp_sizes[item] == 8 )  ret += mkbyte(tcp[item]);
  else if ( tcp_sizes[item] == 16 ) ret += mkword(tcp[item]);
  else if ( tcp_sizes[item] == 32 ) ret += mkdword(tcp[item]);
  else if ( item == "options" )
	{
	  if ( strlen(tcp[item]) % 4 ) tcp[item] += crap(data:mkbyte(0), length:4 - ( strlen(tcp[item]) % 4 ) );
	  ret += tcp[item];
	}
 }
 return ret;
}


function tcp_insert_option(tcp, type, length, data)
{
 local_var pkt;
 if ( isnull(tcp) || tcp["type"] != "tcp" ) 
 { 
  display("tcp_insert_option: bad packet type - ", tcp["type"], "\n");
  return NULL;
 }
 
 pkt = tcp["data"];
 pkt["options"] += mkbyte(type);
 if ( ! isnull(length) )
 { 
  pkt["options"] += mkbyte(length);
  pkt["options"] += data;
 }

 pkt["th_off"] = (  20 + strlen(pkt["options"]) ) / 4;
 tcp["data"] = pkt;
 return tcp;
}


function tcp_finish_insert_option(tcp)
{
 local_var pkt;
 if ( isnull(tcp) || tcp["type"] != "tcp" ) 
 { 
  display("tcp_finish_insert_option: bad packet type - ", tcp["type"], "\n");
  return NULL;
 }

 pkt = tcp["data"];
 if ( strlen(pkt["options"]) % 4 )
	pkt["options"] += crap(length:4 - (strlen(pkt["options"]) % 4 ), data:mkbyte(0));

 pkt["th_off"] = 5 + (strlen(pkt["options"]) / 4);
 tcp["data"] = pkt;
 return tcp;
}

