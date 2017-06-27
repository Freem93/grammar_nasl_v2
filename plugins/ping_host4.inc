#TRUSTED aa99e61bffcb7a0c91af7095fec4f9ac322d7f8f9e24237d0ad6f6814af8762df761b14ff2155520f0c7e8a0a18a9aa1c1983da3a7084c4f4fe982207c767c48eb2de4541ce255879469202502465d2d9d574492141df9630fcdefc67a48784e4283fabf2a5be89963306622a6b73e0b35deda116d98565131e31b0848d4dd31f9d2669a3c087e980bee41394b12db5d57de13c32b7181fc0a7d5cf2d9c8b6ab94de40d62b5875e6ed6a239afb13ae0cd4c5dcb39c329587075ae5eb0c3326dae803cfeb59d0a384784096de023ef47732b3729d9d2eea22dea765df956c65ae4495004fdb4ec7f0ff151d928444be764b8a9a9cfc8dc5916d799c2587e49c4438720baeae324d3414fd5370c58fba949c7159be7a2c364fba2aa8d71a00fed9a9a4af24132c7c6df2cc0cb7ee5d2e0b1c2f50d223c17e7f372d2420c46d450749803be661528d3aa8db51a95bf723005709bd33abbee846364e293e64998ab32f289e9b3285fd1ec4693b04352e9d04b04e0619850a60a12a31b831a94886d5739504f6dba5db55c1f98626a3d3782a03ddf16e9baf4b6323fd655e829386c9a132c57039fcf62b15929cf6828fde32eb4635aa9dda78a2edad0cdb583a89dd464a8d7e4b1889b02633a637f97cf61e55894086ecea894887757de764fa54b527ae8b95842af9e376df105c45e0cc12f1bb6ad782327edc4a6893df5b96f274
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# ping_host4.inc
# v1.7

function TCP()
{
 local_var dport, sport;
 dport = _FCT_ANON_ARGS[0];
 sport = _FCT_ANON_ARGS[1];
 if ( sport == 0 ) sport = rand() % 64511 + 1024;
 return make_list(IPPROTO_TCP, dport, sport);
}

function ICMP()
{
 return make_list(IPPROTO_ICMP, -1, -1);
}

function UDP()
{
 local_var dport, sport, req;
 dport = _FCT_ANON_ARGS[0];
 sport = _FCT_ANON_ARGS[1];
 if ( sport == 0 ) sport = rand() % 64511 + 1024;
 req   = _FCT_ANON_ARGS[2];
 return make_list(IPPROTO_UDP, dport, sport, req);
}

function list()
{
 local_var ret;
 local_var i;
 ret = make_list();
 for ( i = 0 ; i < max_index(_FCT_ANON_ARGS) ; i ++ ) ret[i] = _FCT_ANON_ARGS[i];
 return ret;
}

function merge()
{
 local_var a, b;
 local_var i, n;
 a = _FCT_ANON_ARGS[0];
 b = _FCT_ANON_ARGS[1];
 if ( isnull(a) ) return b;
 if ( isnull(b) ) return a;
 n = max_index(a);
 for ( i = 0 ; i < max_index(b) ; i ++ )
 {
  a[n++] = b[i];
 }
 return a;
}

function insert_icmp()
{
 local_var list;
 local_var ret;
 local_var i, j;
 local_var num;
 local_var retry;

 retry = script_get_preference("Number of retries (ICMP) :");
 if ( int(retry) == 0 ) retry = 2;


 ret = make_list();
 list = _FCT_ANON_ARGS[0];
 num = 0;
 j = 0;
 for ( i = 0 ; i < max_index(list); i ++ )
 {
  if ( i % retry == 0 && num < retry ) { ret[j++] = ICMP(); num++; }
  ret[j++] = list[i];
 }
 for ( i = num ; i < retry ; i ++ ) ret[j++] = ICMP();
 return ret;
}

function tcp_flags()
{
 local_var f;
 local_var ret;
 local_var sep;
 f = _FCT_ANON_ARGS[0];
 sep = "";
 if ( f & TH_FIN ) {  ret += strcat(sep, "FIN"); sep = ","; }
 if ( f & TH_SYN ) {  ret += strcat(sep, "SYN"); sep = ","; }
 if ( f & TH_RST)  {  ret += strcat(sep, "RST"); sep = ","; }
 if ( f & TH_PUSH) {  ret += strcat(sep, "PUSH"); sep = ","; }
 if ( f & TH_ACK) {  ret += strcat(sep, "ACK"); sep = ","; }
 if ( f & TH_URG) {  ret += strcat(sep, "URG"); sep = ","; }
 return ret;
}

function icmp_unreach()
{
 local_var pkt;
 local_var ip, icmp, proto;
 local_var type;

 if ( interpret_icmp_unreach != "yes" ) return FALSE;
 if ( TARGET_IS_IPV6 ) return FALSE;

 pkt = packet_split(_FCT_ANON_ARGS[0]);
 if ( isnull(pkt) ) return FALSE;

 ip = pkt[0];
 ip = ip["data"];
 proto = ip["ip_p"];
 if ( ip["ip_src"] == get_host_ip() ) return FALSE;
 if ( proto != IPPROTO_ICMP ) return FALSE;

 icmp = substr(_FCT_ANON_ARGS[0], ip["ip_hl"] * 4, strlen(_FCT_ANON_ARGS[0]) - 1);
 if ( ! strlen(icmp) ) return FALSE;
 type = ord(icmp[0]);
 if ( type == 3 ) return TRUE;
}

function find_reason(pkt, times)
{
 local_var now;
 local_var i, ip;
 local_var proto, sport, dport;
 local_var reason, reason1;
 local_var icmp, type;
 local_var raw;
 local_var dt;

 raw = pkt;
 now = unixtime();
 pkt = packet_split(pkt);
 ip = pkt[0];
 ip = ip["data"];
 proto = ip["ip_p"];
 if ( proto == IPPROTO_ICMP ) 
 {
  sport = dport = -1;
  icmp = substr(raw, ip["ip_hl"] * 4, strlen(raw) - 1);
  if ( strlen(icmp) ) type = ord(icmp[0]);
  else type = 0;
  
  if ( type == 0 ) {
	 reason = "The remote host replied to an ICMP echo packet";
	 reason1 = "The remote host sent an ICMP echo-reply packet";
	 set_kb_item(name: "/tmp/ping/ICMP", value: TRUE);
  }
  else if ( type == 3 ) {
 	 reason1 = reason = "The remote host replied with an ICMP unreach packet.";
	 if ( strlen(icmp) > 8 )
	 {
	 icmp = substr(icmp, 8, strlen(icmp) - 1);
	 if ( ord(icmp[0]) == 0x45 )
	 {
	  pkt = packet_split(icmp);
	  ip = pkt[0];
	  ip = ip["data"];
	  if ( ip["ip_p"] == IPPROTO_TCP )
	   {
	    ip = pkt[1];
	    ip = ip["data"];
            reason = "The remote host replied with an ICMP unreach packet sent in response to a TCP ";
            if (!isnull(ip["th_flags"])) reason += tcp_flags(ip["th_flags"]) + " ";
	    reason += "packet sent to port " + ip["th_dport"];
	    reason1 = reason;
	    set_kb_item(name: "/tmp/ping/TCP", value: ip["th_dport"]);
  	   }
	  else if ( ip["ip_p"] == IPPROTO_UDP )
	   {
	    ip = pkt[1];
	    ip = ip["data"];
	    reason = "The remote host replied with an ICMP unreach packet sent in response to a UDP packet sent to port " + ip["uh_dport"];
	    reason1 = reason;
	    set_kb_item(name: "/tmp/ping/UDP", value: ip["uh_dport"]);
  	   }
	 }
	}
  }
  else {
	reason = "The remote host replied with an ICMP packet of type " + type;
	reason1 = reason;
	set_kb_item(name: "/tmp/ping/ICMP", value: TRUE);
	}
 }
 else if ( proto == IPPROTO_TCP )
 {
  ip = pkt[1];
  ip = ip["data"];
  sport = ip["th_sport"];
  dport = ip["th_dport"];
  reason = "The remote host replied to a TCP SYN packet sent to port " + sport + " with a " + tcp_flags(ip["th_flags"]) + " packet";
  reason1 = "The remote host emitted a TCP " + tcp_flags(ip["th_flags"]) + " packet from port " + sport + " going to port " + dport;
  set_kb_item(name: "/tmp/ping/TCP", value: sport);
 }
 else if ( proto == IPPROTO_UDP )
 {
  ip = pkt[1];
  ip = ip["data"];
  sport = ip["uh_sport"];
  dport = ip["uh_dport"];
  reason = "The remote host replied to a UDP packet sent to port " + sport;
  reason1 = "The remote host emited a UDP packet from port " + sport + " going to port " + dport;
  set_kb_item(name: "/tmp/ping/UDP", value: sport);
 }
 else reason1 = "The remote host emitted some traffic that the scanner caught";

 for ( i = 0 ; i < max_index(times) ; i ++ )
 {
  pkt = times[i];
  if ( pkt[0] == proto && pkt[1] == sport && pkt[2] == dport && !isnull(pkt[3]) ) 
   {
    dt = difftime2(t1:pkt[3], t2:gettimeofday());
    if ( !isnull(dt) ) return make_list(reason, dt);
   }
 } 

 # Did not find the probe - is the host simply contacting us?
 pkt = times[0];
 dt = difftime2(t1:pkt[3], t2:gettimeofday());
 if ( !isnull(dt) ) 
	return make_list(reason1, dt);
 else 
	return make_list(reason1);
}



function ping_host4(tcp_ports)
{
 local_var tcp, udp;
 local_var probes, rtt, then, now, i, q, pkt, res, s, to, filter, bpf;
 local_var dport;
 local_var cnt;
 local_var ip;
 local_var buf;


 if ( islocalhost() ) return NULL;
 if ( isnull(LinkLayer) ) 
 {
  LinkLayer = link_layer();
  if ( isnull(LinkLayer)  ) return NULL;
 }

 if ( TARGET_IS_IPV6 ) filter = "ip6 and src host " + get_host_ip();
 else 
 { 
  filter = "ip and src host " + get_host_ip();
  if ( interpret_icmp_unreach == "yes" )
  {
   ip = split(get_host_ip(), sep:'.', keep:FALSE);
   filter = "(" + filter + ") or ( icmp and icmp[0:1] = 3 ";
   for ( i = 0 ; i < 4 ; i ++ ) filter += strcat(" and icmp[", (i + 24), ":1] = ", ip[i]);
   filter += ")";
  }
 }

 bpf = bpf_open(filter);
 if ( ! bpf ) return NULL;

 if ( isnull(tcp_ports) ) tcp_ports = defportlist;

 if ("extended" >< tcp_ports )
   tcp_ports = ereg_replace(string: tcp_ports, pattern: "(^|;)extended(;|$)", replace: "\1built-in;110;113;143;264;389;1454;1723;3389\2");

 if ( "built" >< tcp_ports )
  tcp = list(TCP(139, 0), 
	        TCP(135, 0), 
		TCP(445, 0), 
		TCP(80, 0), 
		TCP(22, 0), 
		TCP(515, 1023), 
		TCP(23, 0), 
		TCP(21, 0), 
		TCP(6000, 0), 
		TCP(1025, 0), 
		TCP(25, 0), 
		TCP(111,0), 
		TCP(1028, 0),
	        TCP(9100, 0), 
	        TCP(1029, 0), 
	        TCP(79, 0), 
	        TCP(497, 0), 
	        TCP(548, 0), 
	        TCP(5000, 0), 
	        TCP(1917, 0), 
	        TCP(53, 53), 
	        TCP(161, 0), 
	        TCP(9001, 0), 
	        TCP(49000, 20), 
	        TCP(443, 0), 
	        TCP(993, 0), 
	        TCP(8080, 0), 
	        TCP(2869, 0));

 # Change wrong delimiters
 tcp_ports = ereg_replace(string: tcp_ports, pattern:'[ ,]+', replace: ';');

 foreach dport (split(tcp_ports, sep: ';', keep: 0))
 {
  if ( int(dport) > 0 && int(dport) < 65536 ) tcp = merge(tcp, list(TCP(int(dport), 0)));
 }



 udp = list(UDP(53, 53,  
		strcat(mkword(rand())  ,
                '\x00\x00',             # Standard query (not recursive)
                '\x00\x01',             # 1 question
                '\x00\x00',             # 0 answer RR
                '\x00\x00',             # 0 authority RR
                '\x00\x00',             # 0 additional RR
                '\x03www', '\x07example', '\x03com', '\x00',
                '\x00\x01',             # Type A
                '\x00\x01'              # Classe IN
           ) ),
	   UDP(111, 0, 
		strcat(mkdword(rand()),
	        '\x00\x00\x00\x00',     # Call
                '\x00\x00\x00\x02',     # RPC version = 2
                '\x00\x01\x86\xA0',     # Programm = portmapper (10000)
                '\x00\x00\x00\x02',     # Program version = 2
                '\x00\x00\x00\x03',     # Procedure = GETPORT(3)
                '\0\0\0\0\0\0\0\0',     # Null credential
                '\0\0\0\0\0\0\0\0',     # Null verifier
                '\x00\x00\x27\x10',     # programm 10000
                '\x00\x00\x00\x02',     # version 2
                '\x00\x00\x00\x11',     # UDP = 17
                '\x00\x00\x00\x00'      # port
	  ) ),
	 UDP(520, 520,
		raw_string(1, 1, 0, 0, 0, 0, 0, 0, 
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 16) ),
	 UDP(520, 0, 
		raw_string(1, 2, 0, 0, 0, 0, 0, 0, 
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 16) ),
	 UDP(123, 123, '\xe3\x00\x04\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xC6\x34\xFF\xE6\x4B\xAE\xAB\x79')
	);


 if ( do_tcp == "no" ) tcp = make_list();
 else meth_tried += '- TCP ping\n';

 if ( do_udp != "yes" ) udp = make_list();
 else meth_tried += '- UDP ping\n';

 if ( do_icmp != "no" )
 {
  probes = insert_icmp(merge(tcp, udp));
  meth_tried += '- ICMP ping\n';
 }
 else probes = merge(tcp, udp);
 
 rtt = make_list();
 then = unixtime();

 for ( i = 0 ; i  < max_index(probes) ; i ++ )
 {
  q = probes[i];
  if ( q[0] == IPPROTO_TCP )
  {
   pkt = tcp(th_dport:q[1], th_sport:q[2], th_flags:TH_SYN);
   pkt = tcp_insert_option(tcp:pkt, type:0x02, length:0x04, data:'\x05\xB4');  # Maximum segment size = 1460
   pkt = tcp_insert_option(tcp:pkt, type:0x01);  # NOP
   pkt = tcp_insert_option(tcp:pkt, type:0x01);  # NOP
   pkt = tcp_insert_option(tcp:pkt, type:0x04, length:0x02);  # SACK permitted
   
   if ( TARGET_IS_IPV6 ) pkt = mkpacket(ip6(), pkt);
   else pkt = mkpacket(ip(), pkt);
  }
  else if ( q[0] == IPPROTO_ICMP)
  {
  if ( TARGET_IS_IPV6 ) pkt = mkpacket(ip6(), icmp(ih_type:128, ih_code:0, ih_seq:rand() % 65535));
   else pkt = mkpacket(ip(), icmp(ih_type:8, ih_code:0, ih_seq:rand() % 65535));
  }
  else if ( q[0] == IPPROTO_UDP)
  {
   if ( TARGET_IS_IPV6 ) pkt = mkpacket(ip6(), udp(uh_dport:q[1], uh_sport:q[2]), payload(q[3]));
   else pkt = mkpacket(ip(), udp(uh_dport:q[1], uh_sport:q[2]), payload(q[3]));
  }
  rtt[i] = make_list(q[0], q[1], q[2], gettimeofday());
  inject_packet(packet:LinkLayer + pkt);
  cnt++;

  if ( UseBpfNextWorkaround == TRUE ) 
  {
   if ( cnt >= 3 )
   {
    # In Nessus < 4.4, bpf_next() might wait at least 500ms, no matter what timeout 
    # we set
    res = bpf_next(bpf:bpf, timeout:170);
    cnt = 0;
   }
   else usleep(100000);
  }
  else res = bpf_next(bpf:bpf, timeout:170);

  if ( res ) { 
	buf = substr(res, strlen(LinkLayer), strlen(res) - 1);
	if ( icmp_unreach(buf) )
	{
	 bpf_close(s);
	 return NULL;
	}
	s = find_reason(pkt:buf, times:rtt);
	break;
	}
 }

 if ( isnull(s) )
 {
 #
 # Wait for the left-overs
 # 
 now = unixtime();
 to = get_read_timeout();
 if ( now - then < to )
  {
  res = bpf_next(bpf:bpf, timeout:to - (now - then));
  if ( !isnull(res) ) 
  {
   buf = substr(res, strlen(LinkLayer), strlen(res) - 1);
   if ( icmp_unreach(buf) )
   {
 	bpf_close(s);
	return NULL;
   }
   s = find_reason(pkt:buf, times:rtt);
   }
  }
 }

 bpf_close(bpf);
 return s;
}

