#TRUSTED 8c5f5cf67c5f2b1bb94e132d19b0b4bb4a6e095e45077af2d59a2302dbd62698972135b3e8361e122f5df60c211758d9f7655753d4fd24320fb8649a1f48421fa5404507396b973ae514ee1e322596195a6a7e30a52cf115681a111b5b4c05c923d695c833cb2a873c1743659a6e7015e94bb3672ed2680205e7e692127ada79e16350aa6a77afaccbdf246769f22b3b0cc491d808114f7253c688e08b771f44e328dbecd1b48c0a0278bb866494074ef9a62d3da0e457864d307edc76f2f1aff6c0b3448523fe49f59220203384c29d61caccaea37a7a63fa452584d89c7555b1187e3573fefe1f5d004d19612f6b42e8f72edae475a61b299d53fdd09ea80860d6417d6f8cda938c797fc9bde39de8c417336ef7e81af32b17337915ca07833222daa1dd48fbf6374aa0e766f1ec53e9d6d1c69402d60de6ef6ad9478771884b2a7e0f61604581a269f0ba9074129573748ee13ad19a58ee7521e17bccc40a96f4b41bad7cc10e60287d5100e4b80af829a8fc5a952a8ee6b848322f91a87e991dfa3fb4d9d76ef2796d8a91e0ae859ce419bc013cdc81fb0e55ed1bad4a6df5eecee08c0e4b4172a8ca8757c1a9f1ef91c2a37230117e82094ee00c738c87cbffb16457825e8fb5b10e300d1c8af0908e086d1cd6e985e724e254e0c21cba0d620c08821b0fdeb1fc4821ca9487a003dddf285b96df25caebb75724f13d42
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# These packet forgery-related scripts require Nessus3+ to work properly.
#

global_var RawSendViaOperatingSystem;
include("byte_func.inc");
include("ip.inc");
include("ip6.inc");
include("udp.inc");
include("tcp.inc");
include("icmp.inc");


RawSendViaOperatingSystem = 0;


set_byte_order(BYTE_ORDER_BIG_ENDIAN);



function inet_sum()
{
  local_var     sum, i, n, data;

  data = _FCT_ANON_ARGS[0];
  n = strlen(data);
  sum = 0;
  for (i = 0; i < n - 1; i += 2)
  {
    sum = sum + ord(data[i]) * 256  + ord(data[i+1]);
  }
  if (i < n)
    sum += ord(data[i]);
  sum = (sum >>> 16) + (sum & 0xffff);
  sum += (sum >>> 16);
  sum = (~sum) & 0xffff;
  return sum;
}


function packettype()
{
 local_var ret, v, p, proto, buf;

 ret = NULL;
 buf = _FCT_ANON_ARGS[0];
 v = ord(buf[0]) >> 4;
 if ( v == 0x04 ) 
 {
  p["type"] = "ip";
  p["data"] = buf;
  ret[0] = p;
  proto = ip_get(ip:buf, element:"ip_p");
  if ( proto == IPPROTO_TCP )
	p["type"] = "tcp";
  else if ( proto == IPPROTO_UDP )
 	p["type"] = "udp";
  else if ( proto == IPPROTO_ICMP )
	p["type"] = "icmp";
  else p["type"] = "unknown";
 }
 else if ( v == 0x06 )
 {
  p["type"] = "ip6";
  p["data"] = buf;
  ret[0] = p;
  proto = ip6_get(ip6:buf, element:"ip_nxt");
  if ( proto == IPPROTO_TCP )
	p["type"] = "tcp";
  else if ( proto == IPPROTO_UDP )
 	p["type"] = "udp";
  else if ( proto == 58)	# ICMPv6
	p["type"] = "icmp";
  else p["type"] = "unknown";
 }
  
 
  return ret;
}


function ipaddr()
{
 local_var array, ret;
 array = split(_FCT_ANON_ARGS[0], sep:'.', keep:0);
 ret = raw_string(int(array[0]), int(array[1]), int(array[2]), int(array[3]));
 return ret;
}


#---------------------------------------------------------------------------#
function payload()
{
 local_var ret;

 ret["type"] = "payload";
 ret["data"] = _FCT_ANON_ARGS[0];
 return ret;
}

#---------------------------------------------------------------------------#

function mkpacket()
{
 local_var i, p,sum;
 local_var ret, type, ip;
 for ( i = max_index(_FCT_ANON_ARGS) - 1 ; i >= 0  ; i -- )
 {
  p = _FCT_ANON_ARGS[i];
  if ( p["type"] == "ip" )
	{
	 p = ip_set(ip:p, ip_len:strlen(ret) + ip_get(ip:p, element:"ip_hl") * 4 );
	 type = _FCT_ANON_ARGS[i + 1];
	 if ( ! isnull(type) )
	 {
	  type = type["type"];
	  if ( type == "icmp" ) p = ip_set(ip:p, ip_p:IPPROTO_ICMP);
	  else if ( type == "igmp" ) p = ip_set(ip:p, ip_p:IPPROTO_IGMP);
	  else if ( type == "icmp" ) p = ip_set(ip:p, ip_p:IPPROTO_ICMP);
	  else if ( type == "tcp" ) p = ip_set(ip:p, ip_p:IPPROTO_TCP);
	  else if ( type == "udp" ) p = ip_set(ip:p, ip_p:IPPROTO_UDP);
	 }

	 
	 sum = ip_get(ip:p, element:"ip_sum");
	 if ( sum == 0 )	 
		p = ip_set(ip:p, ip_sum:ip_csum(p));

	 ret = mkip(p) + ret;
	} 
  if ( p["type"] == "ip6" )
	{
	 p = ip6_set(ip6:p, ip6_plen:strlen(ret) );
	 type = _FCT_ANON_ARGS[i + 1];
	 if ( ! isnull(type) )
	 {
	  type = type["type"];
	  if ( type == "icmp" ) p = ip6_set(ip6:p, ip6_nxt: 58); # ICMPv6
	  else if ( type == "igmp" ) p = ip6_set(ip6:p, ip6_nxt:IPPROTO_IGMP);
	  else if ( type == "tcp" ) p = ip6_set(ip6:p, ip6_nxt:IPPROTO_TCP);
	  else if ( type == "udp" ) p = ip6_set(ip6:p, ip6_nxt:IPPROTO_UDP);
	 }
	 ret = mkip6(p) + ret;
	} 
  if ( p["type"] == "tcp" )
	{
	 sum = tcp_get(tcp:p, element:"th_sum");
	 if ( sum == 0 )
		p = tcp_set(tcp:p, th_sum:tcp_checksum(tcp:p, ip:_FCT_ANON_ARGS[i - 1], payload:ret));

	  ret = mktcp(p) + ret;
	} 
  if ( p["type"] == "udp" )
	{
	p = udp_set(udp:p, uh_ulen:strlen(ret) + 8 );
	sum = udp_get(udp:p, element:"uh_sum");
	if (  sum == 0 )
		p = udp_set(udp:p, uh_sum:udp_checksum(udp:p, ip:_FCT_ANON_ARGS[i - 1], payload:ret));

	 ret = mkudp(p) + ret;
	}

  if ( p["type"] == "icmp" )
	{
	 sum = icmp_get(icmp:p, element:"ih_sum");
	 if ( sum == 0 )
		p = icmp_set(icmp:p, ih_sum:icmp_checksum(icmp:p, ip:_FCT_ANON_ARGS[i - 1], payload:ret));

	  ret = mkicmp(p) + ret;
	} 

  if ( p["type"] == "payload" )
	ret = p["data"] + ret;
 }

 return ret;
}


function split_udp(blob, ptr, ret)
{
 local_var item, pkt, c;

 foreach item ( udp_struct )
 {
  if ( udp_sizes[item] == 16 )
	{
	pkt[item] = getword(pos:ptr, blob:blob);
	ptr += 2;
	}
 }

 c["type"] = "udp";
 c["data"] = pkt;

 ret[1] = c;
 ret[2] = payload(substr(blob, ptr, strlen(blob) - 1));
 return ret;
}

function split_tcp(blob, ptr, ret)
{
 local_var item, pkt, c, n, b;
 foreach item ( tcp_struct )
 {
 if ( tcp_sizes[item] == 4 )
	{
	  if ( n == 0 )
		{
	  	  b = getbyte(blob:blob, pos:ptr);
		  pkt[item] = b >> 4;
		  n = 1;
		}
	  else
		{
		 b = getbyte(blob:blob, pos:ptr);
		 pkt[item] = b & 0x0F;
		 n = 0;
		 ptr ++;
		}
	}
  else if ( tcp_sizes[item] == 8 )
	{
	  pkt[item] = getbyte(blob:blob, pos:ptr);
	  ptr ++;
	}
  else if ( tcp_sizes[item] == 16 )
	{
	  pkt[item] = getword(blob:blob, pos:ptr);
	  ptr += 2;
	}
  else if ( tcp_sizes[item] == 32 )
	{
	  pkt[item] = getdword(blob:blob, pos:ptr);
	  ptr += 4;
	}
 }

 if ( pkt["th_off"] > 5 )
	{
	 pkt["options"] = substr(blob, ptr, ptr + (pkt["th_off"] - 5) * 4 - 1);
	 ptr += (pkt["th_off"] - 5) * 4;
	}

 c["type"] = "tcp";
 c["data"] = pkt;
 ret[1] = c;
 ret[2] = payload(substr(blob, ptr, strlen(blob) - 1));

 return ret;
}

function packet_split()
{
 local_var blob;
 local_var ret, pkt, item, n, b, ptr,c;


 blob = _FCT_ANON_ARGS[0]; 
 if ( ! blob || strlen(blob) < 20 ) return NULL;
 ptr = 0;

 
 foreach item ( ip_struct ) 
 {
  if ( ip_sizes[item] == 4 ) 
	{
	 if ( n == 0 )
	 {
	   b = getbyte(pos:ptr, blob:blob);
	   pkt[item] = b >> 4;
	   n ++;
	 }
	 else {
	   b = getbyte(pos:ptr, blob:blob);
	   pkt[item] = b & 0x0F;
	   n = 0;
	   ptr ++;
	  }
	}

 else if ( ip_sizes[item] == 8 )
	{
	 pkt[item] = getbyte(pos:ptr, blob:blob);
	 ptr ++;
	}
 else if ( ip_sizes[item] == 16 )
	{
	pkt[item] = getword(pos:ptr, blob:blob);
	ptr += 2;
	}
  else if ( ip_sizes[item] == 32 )
	{
	pkt[item] = getdword(pos:ptr, blob:blob);
	ptr += 4;
	}
 }

 if ( pkt["ip_hl"] > 5 )
	{
	 pkt["options"] = substr(blob, ptr, ptr + ( (pkt["ip_hl"] - 5 ) * 4) - 1);
	 ptr += ( (pkt["ip_hl"] - 5 ) * 4);
	}

 c["type"] = "ip";
 c["data"] = pkt;
 ret[0] = c;

 if ( pkt["ip_p"] == IPPROTO_UDP )
	ret = split_udp(blob:blob, ptr:ptr, ret:ret);
 else if ( pkt["ip_p"] == IPPROTO_TCP )
	ret = split_tcp(blob:blob, ptr:ptr, ret:ret);


 return ret;

 
 
}
