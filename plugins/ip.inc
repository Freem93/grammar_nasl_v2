#TRUSTED 20949e0ad6b8e9307889307d0f2c6da701271289cee6add96532e32a7e378bc27076417401bc14752e89dd7094f8271b15e11d478d86c6acd5b7fa941c9f6563771ebcfc10824d8fab181bc30a02f3325c6a52d371dfc51cbbe2f9d678594e0b37715d4bece729c3c00f18024c23feaa6633b836bdf996b7c7e5c5dc7effd7c37f2871c6f855fadf8015ece1ed3591051d88beeaa9cc268ebcf6198c9e1eee01f5f28d010c3fdea74a4fa5ecef8f125bb0f4eb6528ff354713f78f052b458270cf19d0dee415a1bd9f1a8f83cf0db12a7efdd51295868a196f623dcb0e8149a34627bb516501435b285412b6336b30ffee81e70c932be30bf5a2b7fe843bb5e19ff072a12672ba25f62a28d7262d254eb33c0a3b7efa6f38bfc0d8f8f66a410f84023789353fdca36083ed07287d4fe208a18cf74666b03aad602be6452d4fd018a0da2cee544710641c9381e1be82d5ced5c88be9315765a9ec65c708bf5243ffc636dfb667cf9bf852ffd05bee16df2e0fd65af33278c7f4de94315c8a2caf332cb3017ad0abccfe0f2ced6cf996c9b551cfde339c4668c4f96e747e111a19c5584a002ab504487d708a69d4d0090f65669df98da8b8fbfbc1479f56430c5df1196326551ce4058e095dcf1d5f23a3c3f588ea49260cd98f7228e303ad3ec09ab99657dbcf4fc5402ca0fa84b18fd2c108a81f0427f3ea6864bb96801e5216
#
# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
#
# @NOGPL@
#
#

#----------------------------------------------------------------------------#
# IP									     #
#----------------------------------------------------------------------------#


#
# Definition of the IP structure
#

ip_sizes = make_array(
		"ip_v",  4,
		"ip_hl", 4,
		"ip_tos",8,
		"ip_len",16,
		"ip_id", 16,
		"ip_off",16,
		"ip_ttl",8,
		"ip_p",  8,
		"ip_sum",16,
		"ip_src",32,
		"ip_dst",32);

ip_struct = make_list("ip_v", 
		      "ip_hl", 
		      "ip_tos", 
		      "ip_len", 
		      "ip_id", 
		      "ip_off", 
		      "ip_ttl", 
		      "ip_p", 
		      "ip_sum", 
		      "ip_src", 
		      "ip_dst",
		      "options");



#
# Compute the checksum of an IP packet
#
function ip_csum()
{ 
 local_var p, pk;
 p = _FCT_ANON_ARGS[0];
 if ( isnull(p) || p["type"] != "ip" )
 {
  display("ip_csum: bad type - ", p["type"], "\n");
  return NULL;
 }
 
 pk = mkip(p);
 return inet_sum(pk);
}




#
# Set any IP element
#

function ip_set(ip, ip_hl, ip_v, ip_tos, ip_len, ip_id, ip_off, ip_ttl, ip_p, ip_sum, ip_src, ip_dst, options )
{
 local_var head,  t;
 local_var ret;

 if ( ip["type"] != "ip" )
	return ip;

 ip = ip["data"];
 
 if ( ! isnull(ip_v) )  ip["ip_v"] = ip_v;
 if ( ! isnull(ip_hl) ) ip["ip_hl"] = ip_hl;
 if ( ! isnull(ip_tos)) ip["ip_tos"] = ip_tos;
 if ( ! isnull(ip_len)) ip["ip_len"] = ip_len;
 if ( ! isnull(ip_id))  ip["ip_id"] = ip_id;
 if ( ! isnull(ip_off)) ip["ip_off"] = ip_off;
 if ( ! isnull(ip_ttl)) ip["ip_ttl"] = ip_ttl;
 if ( ! isnull(ip_p))   ip["ip_p"] = ip_p;
 if ( ! isnull(ip_sum)) ip["ip_sum"] = ip_sum;
 if ( ! isnull(ip_src)) ip["ip_src"] = ip_src;
 if ( ! isnull(options))ip["options"] = options;
 if ( ! isnull(ip_dst)) ip["ip_dst"] = ip_dst;


 ret["data"] = ip;
 ret["type"] = "ip";
 return ret;
} 


#
# Create a fresh new packet, with useful default values
#
function ip( ip_hl, ip_v, ip_tos, ip_len, ip_id, ip_off, ip_ttl, ip_p, ip_sum, ip_src, ip_dst, options)
{
 local_var empty;
 if ( isnull(ip_hl) )  ip_hl = 5;
 if ( isnull(ip_v)  )  ip_v  = 4;
 if ( isnull(ip_tos))  ip_tos = 0;
 if ( isnull(ip_len))  ip_len = 20;
 if ( isnull(ip_id ) ) ip_id  = rand() % 65534  + 1;
 if ( isnull(ip_off) ) ip_off = IP_DF;
 if ( isnull(ip_ttl) ) ip_ttl = 128;
 if ( isnull(ip_p)   ) ip_p   = IPPROTO_TCP;

 if ( isnull(ip_src) ) ip_src = this_host();
 if ( isnull(ip_dst) ) ip_dst = get_host_ip();

 empty["type"] = "ip";
 empty["data"] = NULL;

 return ip_set(ip:empty,
	       ip_v:ip_v,
	       ip_hl:ip_hl,
	       ip_tos:ip_tos,
	       ip_len:ip_len,
	       ip_id:ip_id,
	       ip_off:ip_off,
	       ip_ttl:ip_ttl,
	       ip_p:ip_p,
	       ip_sum:ip_sum,
	       ip_src:ip_src,	
	       ip_dst:ip_dst,	
	       options:options);
}



#
# Get any item in our IP packet
#
function ip_get(ip, element)
{
 local_var t, l, ret;
 if ( isnull(ip) || ip["type"] != "ip" )
 {
  display("ip_get: invalid 'ip' argument\n");
  return NULL;
 }
 ip = ip["data"];
 return ip[element];
}


#
# Insert an IP option in our packet
#
function ip_insert_option(ip, option)
{
 local_var pkt;

 if ( isnull(ip) || ip["type"] != "ip" )
 {
  display("ip_insert_option: invalid 'ip' argument\n");
  return NULL;
 }

 if ( isnull(option) || option["type"] != "ip_option") 
 {
  display("ip_insert_option: invalid 'option' argument\n");
  return NULL;
 }

 pkt = ip["data"];
 pkt["options"] += option["data"];
 ip["data"] = pkt;
 
 return ip;
}

#
# Compute the padding for the ip options and update ip->ip_hl
#
function ip_finish_insert_option()
{
 local_var pkt, ip;
 
 ip = _FCT_ANON_ARGS[0];
 if ( isnull(ip) || ip["type"] != "ip" )
 {
  display("ip_insert_option: invalid 'ip' argument\n");
  return NULL;
 }

 pkt = ip["data"];
 if ( strlen(pkt["options"]) % 4 != 0 )
	pkt["options"] += crap(length: 4 - strlen(pkt["options"]) % 4, data:mkbyte(0)); 

 pkt["ip_hl"] = 5 + strlen(pkt["options"]) / 4;
 ip["data"] = pkt;
 return ip;
}


#
# Create an IP option of type <type>, length <length> and data <data>
#
function ip_option(type, length, data)
{
 local_var ret, opt;
 ret["type"] = "ip_option";
 opt = mkbyte(type);
 if ( !isnull(length) ) 
 {
  opt += mkbyte(length);
  opt += data;
 }
 ret["data"] = opt;
 return ret;
}


#
# Transforms an IP structure into a blob which is suitable to be
# sent over the network
#
function mkip()
{
 local_var item, ret, n, b, ip, opt;

 ip = _FCT_ANON_ARGS[0];
 
 if ( ip["type"] != "ip") 
 {
   display("mkip : Bad packet type - ", ip["type"], "\n");
 } 

 ip = ip["data"];

 foreach item ( ip_struct )
 {
  if ( ip_sizes[item] == 4 ) 
	{
	if ( n == 0 )
		{
		 b = ip[item];
		 n = 1;
		}
 	else 	{
		 b = b << 4 | ip[item];
		 ret += mkbyte(b);
		 n = 0;
		}
	}
  else  {
     if ( ip_sizes[item] == 8 )   ret += mkbyte(ip[item]);
     if ( ip_sizes[item] == 16 ) {
		  if ( RawSendViaOperatingSystem && bsd_byte_ordering() && ! big_endian() && ( item == "ip_off" || item == "ip_len") )
			set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
		  ret += mkword(ip[item]);
		  if ( RawSendViaOperatingSystem && bsd_byte_ordering() && ! big_endian() && ( item == "ip_off" || item == "ip_len") )
			set_byte_order(BYTE_ORDER_BIG_ENDIAN);
     }
     if ( ip_sizes[item] == 32 )  ret += ipaddr(ip[item]); # 32bits -> can only be ip_src or ip_dst
     else if ( item == "options") {
	opt = ip[item];
	if ( strlen(opt) % 4  != 0 ) opt += crap(data:mkbyte(0), length: 4 - (strlen(opt) % 4) );
	ret += opt;
	}
   }
 }

 return ret;
}


