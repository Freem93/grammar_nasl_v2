#TRUSTED 6cdfed4bcc0d50961b6bbe48794594268ceea3c49503bccfaaa6e92cdbaba599eb8cd86e2d4bba6e0db759e8b74edad443c4ced8199d7527d6738a25214c54c2d1bbf764d5af7603b429a543131773180a9acd25349e0ef6b68437868712ddf01b85406827c492d6356013036e37abcfd434ccf27a598779637cb12d425c4c5215b719514d68301a2f04cd858139913e5a095b057bfc854b13469555dccf3922b8076e4ae155b21d3f0d481a25eb6d617f41da863673b67126ea26fd86a0f3d6641a1f46ab36793cf00a6283c3b67cf2e23c285b358da5ee27352ff58b7c2b879a9d760f7132d1a2df924912ece3b8f00ae559bd371f77f09547547d2ab0695506f7ff8781418d088feae9c1994f37cccd083b687be21d9adbaab05fd71154e8a1ebe4634e5b8f6333f4fa0d34d866a68810e1adf8c3957108845753b656dbac7fa083f1de6893a0b25d504d5cd04d361609320f1b6cc91053dcaee5b4fee0ec5d5ca41c6fc0e27ed36afa4c79e0a69fc3377d919c7336e06afe0710e04f0d28ecb69fe9bfe66c72672e65bfa1d4d21e564a00ccd49df3b9a25452d82d01ca645b4ad2533283aeb2c6d8975a6384ac601218ee7c57597829e2013765a97f69d6ae4af9fa6db0b914bc64a62b036009f91a1d6ad34d3059fb5fe92beddbd655cc523098feaaafb680cb05d93d25788a4f4c91a3c76c5447cbaa46bf42a3777181
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

ip6_sizes = make_array(
		"ip6_vfc",  8,
		"ip6_flow",   24,
		"ip6_plen",   16,
		"ip6_nxt",     8,
		"ip6_hlim",    8,
		"ip6_src",128,
		"ip6_dst",128);

ip6_struct = make_list("ip6_vfc", 
		      "ip6_class", 
		      "ip6_flow", 
		      "ip6_plen", 
		      "ip6_nxt", 
		      "ip6_hlim", 
		      "ip6_src", 
		      "ip6_dst");





#
# Set any IP element
#

function ip6_set(ip6, ip6_vfc, ip6_flow, ip6_plen, ip6_nxt, ip6_hlim, ip6_src, ip6_dst)
{
 local_var head,  t;
 local_var ret;

 if ( ip6["type"] != "ip6" )
	return ip6;

 ip6 = ip6["data"];
 
 if ( ! isnull(ip6_vfc) )  ip6["ip6_vfc"] = ip6_vfc;
 if ( ! isnull(ip6_flow) ) ip6["ip6_flow"]    = ip6_flow;
 if ( ! isnull(ip6_plen) ) ip6["ip6_plen"]    = ip6_plen;
 if ( ! isnull(ip6_nxt) )  ip6["ip6_nxt"]     = ip6_nxt;
 if ( ! isnull(ip6_hlim) )  ip6["ip6_hlim"]     = ip6_hlim;
 if ( ! isnull(ip6_src) )  ip6["ip6_src"]     = ip6_src;
 if ( ! isnull(ip6_dst) )  ip6["ip6_dst"]     = ip6_dst;

 ret["data"] = ip6;
 ret["type"] = "ip6";
 return ret;
} 


#
# Create a fresh new packet, with useful default values
#
function ip6(ip6_vfc, ip6_flow, ip6_plen, ip6_nxt, ip6_hlim, ip6_src, ip6_dst)
{
 local_var empty;
 if ( isnull(ip6_vfc) )  ip6_vfc   = 6 << 4;
 if ( isnull(ip6_flow) ) ip6_flow = 0;
 if ( isnull(ip6_plen) ) ip6_plen = 0;
 if ( isnull(ip6_nxt) ) ip6_nxt = IPPROTO_TCP;
 if ( isnull(ip6_hlim) ) ip6_hlim = 64;
 if ( isnull(ip6_src ) ) ip6_src = this_host_raw();
 if ( isnull(ip6_dst ) ) ip6_dst = get_host_raw_ip();

 empty["type"] = "ip6";
 empty["data"] = NULL;

 return ip6_set(ip6:empty,
		ip6_vfc:ip6_vfc,
		ip6_flow:ip6_flow,
		ip6_plen:ip6_plen,
		ip6_nxt:ip6_nxt,
		ip6_hlim:ip6_hlim,
		ip6_src:ip6_src,
		ip6_dst:ip6_dst);
}



#
# Get any item in our IP packet
#
function ip6_get(ip6, element)
{
 local_var t, l, ret;
 if ( isnull(ip6) || ip6["type"] != "ip6" )
 {
  display("ip6_get: invalid 'ip6' argument\n");
  return NULL;
 }
 ip6 = ip6["data"];
 return ip6[element];
}




#
# Transforms an IPv6 structure into a blob which is suitable to be
# sent over the network
#
function mkip6()
{
 local_var item, ret, n, b, ip6;

 ip6 = _FCT_ANON_ARGS[0];
 
 if ( ip6["type"] != "ip6") 
 {
   display("mkip6 : Bad packet type - ", ip6["type"], "\n");
 } 

 ip6 = ip6["data"];

 foreach item ( ip6_struct )
 {
     if ( ip6_sizes[item] == 24 )
	{
	 n = ord(ret[strlen(ret) - 1]);
	 ret = substr(ret, 0, strlen(ret) - 2);
	 ret += mkdword(n << 24 | ip6[item]);
	}
     if ( ip6_sizes[item] == 8 )   ret += mkbyte(ip6[item]);
     if ( ip6_sizes[item] == 16 )  ret += mkword(ip6[item]);
     if ( ip6_sizes[item] == 128 ) ret += ip6[item]; # 128bits -> can only be ip_src or ip_dst
 }

 return ret;
}


function _ip6_x2r()
{
 local_var s;
 s = _FCT_ANON_ARGS[0];
 while ( strlen(s) != 4 ) s = strcat('0', s);

 return hex2raw(s:s);
}

function ip6addr()
{
 local_var ip;
 local_var array;
 local_var i, n;
 local_var ret;
 local_var j;


 ip = _FCT_ANON_ARGS[0];
 array = split(ip, sep:':', keep:FALSE);

 n = max_index(array);
 ret = '';

 for ( i = 0 ; i < n ; i ++ )
 {
  if ( ! strlen(array[i]) )
        {
          for ( j = 0 ; j < 8 - n + 1; j ++ )
                ret += '\x00\x00';
          continue;
        }
  ret += _ip6_x2r(array[i]);
 }

 if ( (strlen(ret) * 8) != 128 ) return NULL;
 return ret;
}
