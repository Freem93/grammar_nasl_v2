#TRUSTED 3aae8b0bf8bfe95a2b4d31afef67d67504302ddd9d674a9da5aee7a9c4d76fbebaed759065cf9dd56f7ffffcb1b97dc23d632bd82cb0f7d1fa3d8979f9f7b696b569dbbc09e405eb67af500617374701c3a9c9a70a215b420197a64fa3edebb9c0c70bd05a7d0263bd9778deff57a16eae125bff5f60a9c5ae7f972986b1c4a6950f0a3416c655ffd35012a3ab3010f14027b938b2e70784b27668ecea351d3f4debf1cf1fb2c0b0e6078f07ef00935964f1cdeea38586d3b9e45031a52ca7ac8967b8abad33ac26f33804c3ce44a3f8e762ca1b37adb3c4e891433f457256c6d4b348c3b9690dfb0f2b9b949590a37156fcfe746888cd26d15602df7526493b8f8b754b851fa37d0053703e34082be11c16f78b20ae695996c7674b7adf71b83ce8b56b97caea4683ac8ea564a2eaefb09bf4cc321e0ea6d93c1c7e32bb17777d75adf3532e8148cdfc113bb08e0e16c0b5bf989dd8d9d6949f48c436c750cff3765c92e635c82d6b3285fbd81784b343241b0a40322fceedcb3b2c4b97ad3a5f81036c937ec10e118d844765c7f10e5644511d9766b87c3052c62d15458398adb14c628db4907768df78a381a2c9ca3954daa48ce94fbb1a0c636b09acda65dd35dd8d99a53b7a76e7d6fa755abe9a54c52834b9af247bcbe09863bb342521c9665e08d0bd04c2a5b8bca4dab92c88703af4aff32704ac56fd394b3c44b47a
#
# (C) Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.3


#-------------------------------------------------------------------------#
# ICMP                                                                    #
#-------------------------------------------------------------------------#

ICMPTYPE_UNREACHABLE = 3;
ICMPCODE_NET_UNREACH  = 0;
ICMPCODE_HOST_UNREACH  = 1;
ICMPCODE_PROTO_UNREACH  = 2;
ICMPCODE_PORT_UNREACH  = 3;
ICMPCODE_FRAG_NEEDED  = 4;
ICMPCODE_SOURCE_ROUTE  = 5;

ICMPTYPE_TIME_EXCEEDED = 3;
ICMPTYPE_TTL_EXCEEDED = 0;
ICMPTYPE_FRAG_REASS = 1;

ICMPTYPE_PING = 8;
ICMPTYPE_PONG = 0;

ICMP6TYPE_PING = 128;
ICMP6TYPE_PONG = 129;

# TBD

icmp_sizes = make_array(
	"ih_type",	8,
	"ih_code", 	8,
	"ih_sum",	16,
	"ih_id",	16,
	"ih_seq",	16,
	"ih_data",	-8,
	"ih_gw_addr",	32,
	"ih_orig_ts",	32,
	"ih_rec_ts",	32,
	"ih_trans_ts",	32,
	"ih_ptr",	8,
	"ih_orig_pkt",	-8 );

icmp_offsets = make_array(
	"ih_type",	0,
	"ih_code",	8,
	"ih_sum",	16,
	"ih_id",	32,
	"ih_seq",	48,
	"ih_data",	64,
	"ih_gw_addr",	32,
	"ih_orig_ts",	64,
	"ih_rec_ts",	96,
	"ih_trans_ts",	128,
	"ih_ptr",	32,
	"ih_orig_pkt",	64 );

function icmp_checksum(icmp, ip, payload)
{
 local_var	icmp0, icmp_r, ret,pseudo;

 if ( (ip["type"] != "ip" && ip["type"] != "ip6") || icmp["type"] != "icmp" )
 {
	display("icmp_checksum: Bad IP argument\n");
	return NULL;
 }

 icmp0 = icmp;
 icmp0["ih_sum"] = 0;
 icmp0["ih_data"] = payload;
 icmp_r = mkicmp(icmp0);
 if (ip["type"] == "ip")
 {
   pseudo = icmp_r;
 }
 else if ( ip["type"] == "ip6" )
 {
   ip = ip["data"];
   pseudo = ip["ip6_src"] + 		
           ip["ip6_dst"] + 		
           '\0\0' + 			
           mkword(strlen(icmp_r)) + 	
           '\0\0\0' + 			
           mkbyte(58) +    
           icmp_r;
 }
 ret = inet_sum(pseudo);
 return ret;
}
 
# To be completed
function icmp_set(icmp, ih_type, ih_code, ih_sum, ih_seq, ih_id)
{
 local_var head, tail, ret, t;

 if ( isnull(icmp) )
 {
  display("set_icmp: NULL ICMP packet\n");
  return NULL;
 }

 if ( icmp["type"] != "icmp" )
  {
	display("set_icmp: bad packet type\n");
	return icmp;
	}

 icmp = icmp["data"];

 if ( ! isnull(ih_type) ) icmp["ih_type"] = ih_type;
 if ( ! isnull(ih_code) ) icmp["ih_code"] = ih_code;
 if ( ! isnull(ih_sum) ) icmp["ih_sum"] = ih_sum;
 if ( ! isnull(ih_seq) ) icmp["ih_seq"] = ih_seq;
 if ( ! isnull(ih_id) ) icmp["ih_id"] = ih_id;

# TBD
 ret["type"] = "icmp";
 ret["data"] = icmp;

 return ret;
}


function icmp(ih_type, ih_code, ih_sum, ih_seq, ih_id)
{
 local_var empty;
 # if ( isnull(ih_seq) ) ih_seq = rand() % 0x7fffffff;
 # TBD
 empty["type"] = "icmp";
 empty["data"] = NULL;
 if ( isnull(ih_id) ) ih_id = rand() % 65534 + 1;
 
 return icmp_set(icmp:empty,
	 	ih_type: ih_type, 
		ih_code: ih_code,
		ih_sum: ih_sum, 
		ih_seq: ih_seq,
		ih_id:  ih_id);
}


function icmp_get(icmp, element)
{
 if ( isnull(icmp) || icmp["type"] != "icmp") 
 {
  display("icmp_get: Bad packet type - ", icmp["type"], "\n");
  return NULL;
 }

 icmp = icmp["data"];
 return icmp[element];
}

function mkicmp()
{
 local_var icmp, ret, item,n,b, l;
 local_var	off, sz, blob;

 icmp = _FCT_ANON_ARGS[0];
 if ( icmp["type"] != "icmp" )
 {
  display("mkicmp(): Bad packet type - ", icmp["type"], "\n");
  return NULL;
 }

 icmp = icmp["data"];
 ret =  '\0\0\0\0\0\0\0\0';
 foreach item (keys(icmp_sizes))
 {
   if (isnull(icmp[item])) continue;

   sz = icmp_sizes[item] / 8;
   off = icmp_offsets[item] / 8;

   if ( icmp_sizes[item] == 8 )		blob = mkbyte(icmp[item]);
   else if ( icmp_sizes[item] == 16 )	blob = mkword(icmp[item]);
   else if ( icmp_sizes[item] == 32 )	blob = mkdword(icmp[item]);

   if (off == 0)
     b = '';
   else
   {
     b =  substr(ret, 0, off -1);
     l = strlen(b);
     if (l < off - 1) b = strcat(b, crap(data: '\0', length: off -l - 1));
   }
   if (  sz > 0) 
     ret = strcat(b, blob, substr(ret, off + sz) );
   else	# Variable size
     ret = strcat( b, icmp[item]);
 }
 return ret;
}

