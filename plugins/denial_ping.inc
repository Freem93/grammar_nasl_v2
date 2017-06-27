#TRUSTED 086632f33751313080e64eba20514552483de3604a307da4e6dfb83ca4cb85f4d44eda4d5f51f7477f210a8860b2ad3ea0f9c44c6fa3a8e4f8cce3f37abf04f6f6117f5148ca8a85d70cffece5283a54a9599c2d3017f2b6582f13036d0e8184d9cba9f6e26bb349ce9e4dd81941d9b14ee065b63b0afd7afbf62111698bb38d12af5fd310cb1c7a800c7e1ac8b641c9195777b7a078f6f4d33073d6ee596c847a71fff33cc99f1eba9c48b2890d09cd16fe6d03de8cd250c4ac8f764952007025ce5499e8623d7027ccc0e778fefdd23615b7662d42d426ea046fc6eed5f4f1a585d1406981bdbbaf0e79925f51e9548d82832f36531f462c058f1d820ec842c3364d1f5f177ea87f8e54e9ca8dbb61a641bd08482c33cd5dc873c8076d0e9dbbf6a5b1eae3f86eace11c16e8f0f9125df4b1046cae71c5ca5a9784164a27faeb3539afda5900776591f0fb80b5664e0d6c69d19a4066c012c6d3dd09d51baa8b6228231d5d86b88193aa24aa388d8371a519e930bdd7f2c4aecaab4677d4a9cf5f743d215d7df115593e12261c1e7a8f9c39ef4dabfaebcfc77413a99fd1c3cc7270531353f72a85ecd2c30fb5f49c4e509b20727ba995cdb0bcbbf1ca5e9a1e859f7da8b47be96eb891d89898da8b90c10543d0edf6f12c9e9cef519d94065f1751c7f0b24f18500d4997e32a4b559168e78714903096c5ceaabbdf2af274
#
#
# (C) Tenable Network Security, Inc.
# @NOGPL@
#
#
# This file is used by the functions start_denial()/end_denial(). Do not edit it !!
#

# 
# Utilities
#
function mkbyte()
{
  local_var l;
  l = _FCT_ANON_ARGS[0];
  return raw_string(l & 0xff);
}

function mkword()
{
  local_var l;
  l = _FCT_ANON_ARGS[0];
  return  raw_string((l >> 8) & 0xFF, l & 0xFF);
}

function mkipaddr()
{
  local_var ip;
  local_var str;

  ip = _FCT_ANON_ARGS[0];
  str = split(ip, sep:'.', keep:FALSE);
  return raw_string(int(str[0]), int(str[1]), int(str[2]), int(str[3]));
}

function arp_ping()
{
  local_var broadcast, macaddr, ethernet, arp, r, i, srcip, dstmac, t1, t2;

  broadcast = crap(data:raw_string(0xff), length:6);
  macaddr   = get_local_mac_addr();

  if ( ! macaddr ) return 0;  # Not an ethernet interface

  arp = mkword(0x0806);
  ethernet = broadcast + macaddr + arp;

  arp = ethernet + # Ethernet
        mkword(0x0001) + # Hardware Type
        mkword(0x0800) + # Protocol Type
        mkbyte(0x06)   + # Hardware Size
        mkbyte(0x04)   + # Protocol Size
        mkword(0x0001) + # Opcode (Request)
        macaddr        + # Sender mac addr
        mkipaddr(this_host()) + # Sender IP addr
        crap(data:raw_string(0), length:6) + # Target Mac Addr
        mkipaddr(get_host_ip());

  t1 = gettimeofday();
  for ( i = 0 ; i < 3 ; i ++ )
  {
    r = inject_packet(packet:arp, filter:"arp and arp[7] = 2 and src host " + get_host_ip(), timeout:1);
    if ( r && strlen(r) > 31 )
    {
      t2 = gettimeofday();
      srcip = substr(r, 28, 31);
      if ( srcip == mkipaddr(get_host_ip() ) )
        return 1;
    }
  }
  return 0;
}

# main()

if(islocalhost()) exit(1);
if ( TARGET_IS_IPV6 ) exit(1);
if ( islocalnet() && !TARGET_IS_IPV6 )
  exit(arp_ping());

if (tcp_ping()) exit(1);

# Try ICMP ping
pfilter = "src host " + get_host_ip()+ " and dst host " + this_host() +
" and ( icmp and icmp[0]=0 or tcp )";
# and ((tcp[13] & 23) == 18)

ip = forge_ip_packet(
  ip_v   : 4,
  ip_hl  : 5,
  ip_tos : 0,
  ip_off : 0,
  ip_len : 20,
  ip_p   : IPPROTO_ICMP,
  ip_id  : rand() % 65536,
  ip_ttl : 0x40,
  ip_src : this_host()
);

icmp = forge_icmp_packet(
  ip        : ip,
  icmp_type : 8,
  icmp_code : 0,
  icmp_seq  : rand() % 65536,
  icmp_id   : rand() % 65535
);

# iteratively increase timeout
for (i = 1; i < 4; i ++)
{
  r =  send_packet(icmp, pcap_active:TRUE, pcap_filter: pfilter, pcap_timeout: i);
  if (r) exit(1); # host is alive
}

# Try again TCP
try_ports_l = make_list(22, 23, 53, 79, 111, 113, 135, 139, 143, 264, 389, 443, 445, 497, 515, 548, 993, 1025, 1027, 1454, 1723, 1917, 1028, 1029, 2869, 3389, 5000, 6000, 9100);
foreach port (try_ports_l)
{
  if (get_port_state(port))
  {
    ip = forge_ip_packet(
      ip_v   : 4,
      ip_hl  : 5,
      ip_tos : 0,
      ip_len : 40,
      ip_id  : rand() % 65535,
      ip_p   : IPPROTO_TCP,
      ip_ttl : 64,
      ip_off : 0,
      ip_src : this_host()
    );
    if ( ! ip ) exit(1); # host is alive
    tcp = forge_tcp_packet(
      ip       : ip,
      th_sport : 1024 + rand() % 64512,
      th_dport : port,
      th_flags : TH_SYN,
      th_seq   : rand(),
      th_ack   : 0,
      th_x2    : 0,
      th_off   : 5,
      th_win   : 512
    );
    if ( ! tcp ) exit(1); # host is alive
    r = send_packet(tcp, pcap_active:TRUE, pcap_filter: pfilter, pcap_timeout: 0);
    if (r) exit(1); # host is alive
  }
}

to = int(get_preference("checks_read_timeout")); if (! to) to = 5;
r = pcap_next(pcap_filter: pfilter, timeout: to);
if (r) exit(1); # host is alive

# No answer - host is dead
exit(0); # leave this here - value is consumed by check_denial()
