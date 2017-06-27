#TRUSTED 9aba331c2bcbe7730641ef9f1de202019280f0d3ce01ba3ce4df65e2dd30003ef5b616743bec35b99e742f6aafe3d31636d540519d3ccb9af524209f3ee33d7ae60fa8565ef0ba4917eb3899b9f4bdc4c0a6982d8dd9aa652dc4d82165d4bb29cafb33a7ce1c0d32254b5b4949deab23458278ae9760f732df444ae07eb63e9894121d499e5d8fa88ea542e4916cd4a22378b1c8c27af68a06743bebec095b136a1129405fd03684f6cb2a25d67474b5d4ba4ab56106c0d867e6efea8fd38a1aafa3e64da025f4b6bf753b514c469f57550b0946d7d1ea3a4412b66b8aaff5fcc615be83a2c813df51a2969cf76e4bbb9f2689a89010dace1b3bb83dcbc969387f6929144b3a849a08c6de132a4f7bf88f64779494f605dda2881b43bb331ce81f75898cc0e45edd9dd11706c8c4b2237456e87cc38daa3e9c07261c6f2a9d5187b674a74f9b94e34317f814c8e3ca349ff8ab7d03180ce3805cb521392e3a3ab14175aea26174fb398de14889e1907b4af839e9e10a97c84f3f4642a304c7754c9e4c11c4f053c56a9f3413b7d564d91d6481f16184dd9cff44470bcbe1c4b73ed531a7fefc29a796ef29edaf1b06273ee7406a74aa103f481ffc24856211fe1478c88d3ff9a516d787e7f3aac9e7cccd45eb5c5d646695d2a20ba4a902acc26c9a7e556c780910ac202be1fd3e2f58de7f8ce255953e32b880ca9e5f90f3bc
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
# dns_func.inc 
#
# Revision: 1.14
#

DNS_QTYPE_PTR         = 12;
DNS_QTYPE_SRV         = 33;
DNS_QTYPE_TXT         = 16;
DNS_QTYPE_A           = 1;
DNS_QTYPE_AAAA        = 28;
DNS_QTYPE_HINFO       = 13;
DNS_QTYPE_ANY         = 255;
DNS_QTYPE_RRSIG       = 46;
DNS_QTYPE_NSEC        = 47;
DNS_QTYPE_DNSKEY      = 48;

DNS_QCLASS_IN         = 1;
DNS_QCLASS_CH         = 3;


dns_struct = make_list("transaction_id",
		       "flags",
			"q",
			"an_rr",
			"au_rr",
			"ad_rr");


dns_sizes = make_array("transaction_id",     16,
			"flags",	     16,
			"q",		     16,
			"an_rr",	     16,
			"au_rr",	     16,
			"ad_rr",	     16);


function get_query_txt()
{
 local_var s, l;
 s = _FCT_ANON_ARGS[0];
 if ( isnull(s) ) return NULL;
 l = ord(s[0]);
 return substr(s, 1, l);
}


function get_full_query_txt()
{
 local_var s, l;
 local_var ret;

 s = _FCT_ANON_ARGS[0];
 if ( isnull(s) ) return NULL;
 
 while ( strlen(s) )
 { 
 l = ord(s[0]);
 if ( strlen(ret) > 0 ) ret += ".";
 ret += substr(s, 1, l);
 s = substr(s, l + 1, strlen(s) - 1 );
 }
 return ret;

}

function mk_query_txt()
{
 local_var i, ret;
 for ( i = 0 ; _FCT_ANON_ARGS[i] ; i ++ )
 {
   ret += raw_string(strlen(_FCT_ANON_ARGS[i])) + _FCT_ANON_ARGS[i];
 }
 return ret + raw_string(0);
}

function mk_query(txt, type, class)
{
 return txt + raw_string(type >> 8,  type & 0xff, class >> 8, class & 0xff); 
}

function mk_dns_request(str, type, class, flags, dnssec, is_tcp)
{
 local_var tmp;

 if(isnull(is_tcp)) is_tcp = FALSE;

 # By default assume a standard query.
 if ( isnull(flags) ) flags = 0x100;

 # By default assume class IN as it is nearly universal. 
 if ( isnull(class) ) class = DNS_QCLASS_IN;

 # By default do not request a DNSSEC response.
 if ( isnull(dnssec) ) dnssec = FALSE;

 local_var dns, query;
 dns = make_array("transaction_id", rand() % 65536,
                  "flags",          flags,
                  "q",              1);
 query = mk_query(txt:dns_str_to_query_txt(str), class:class, type:type);

 if(is_tcp)
 {
   tmp = mkdns(dns:dns, query:query, dnssec:dnssec);
   return mkword(strlen(tmp)) + tmp; 
 }
 else
   return mkdns(dns:dns, query:query, dnssec:dnssec);
}

function mkdns(dns, query, dnssec)
{
 # If dnssec is requested, we add an additional RR.
 if ( isnull(dns["ad_rr"]) ) dns["ad_rr"] = 0;
 if ( dnssec ) dns["ad_rr"] = dns["ad_rr"] + 1;

 local_var item, ret;
 foreach item ( dns_struct )
 {
  ret += raw_string(dns[item] >> 8, dns[item] & 0xff);
 }

 ret += query;

 # Add the RR that declares our acceptance of DNSSEC.
 if ( dnssec )
 {
  ret += raw_string(
    0,        # Name: <Root>
    0, 0x29,  # Type: OPT (EDNS0 option)
    0x10, 0,  # UDP payload size: 4096
    0,
    0,        # EDNS0 version: 0
    0x80, 0,  # Accept DNSSEC security RRs
    0, 0      # Data length: 0
  ); 
 }

 return ret;
}

function dns_comp_get(str, offset, rec)
{
 local_var i, o, l, ret;


 if ( ! rec ) rec = 0;
 if ( rec > 4 ) exit(0);

 o = offset;

 while ( TRUE )
 {
  if ( o >= strlen(str) ) break;
  l = ord(str[o]);
  if ( (l & 0xc0) == 0xc0 && (o + 1) < strlen(str) ) {
	o = ord(str[o+1]);
	ret += dns_comp_get(str:str, offset:((l & ~0xc0) << 8) | o, rec:rec+1);
	break;
	}
  else
  {
   if ( o + l > strlen(str) ) return NULL;
   ret += substr(str, o + 1, o + l);
   if ( ord(str[o+l]) == 0 ) break;
   else ret += '.';
   o += l + 1;
  }
 }
 return ret;
}

function dns_str_get(str, blob)
{
 local_var ret, l, offset;

 offset = 0;
 while ( TRUE )
 {
  if ( ( ord(str[offset]) & 0xc0 ) == 0xc0 ) 
	{
	offset = ord(str[offset+1]);
	if ( ret ) return ret + '.' + dns_comp_get(str:blob, offset:offset);
	else return dns_comp_get(str:blob, offset:offset);
	}
   
   l = ord(str[offset]);
   if ( offset + l > strlen(str) ) return ret;
   if( ret) ret += '.' + substr(str, offset + 1, offset + l ); 
   else     ret +=       substr(str, offset + 1, offset + l ); 
   if ( ord(str[offset+l]) == 0 ) break;
   offset += l + 1;
 }
 return ret;
}

# The section arg is one of an, ad, or au (answer, additional, authorized)
function dns_data_get(type, section, response)
{
 local_var contents, ret;
 local_var i, j;
 contents = dns_split(response);
 if (isnull(contents))
 {
   err_print("dns_data_get: response argument must be a valid DNS response");
   return NULL;
 }
 ret = make_list();
 
 j = 0;
 for (i = 0; i < contents[section+"_rr"]; i++)
 {
   local_var actual_type;
   actual_type = contents[section+'_rr_data_'+i+'_type'];
 
   if (actual_type == type)
     ret[j++] = contents[section+"_rr_data_"+i+"_data"];
 }
 
 return ret;
}

function dns_str_to_query_txt()
{
 local_var p, ret;
 ret = "";
 foreach p (split(_FCT_ANON_ARGS[0], sep:".", keep:FALSE))
  ret += raw_string(strlen(p) % 255) + p;
 return ret + raw_string(0);
}


function dns_split()
{
 local_var ret, n, m, item, ptr, p, cur, t, l;
 local_var names, offset, i, tmp, o;


 if ( isnull(_FCT_ANON_ARGS[0])) exit(0);
 p   = _FCT_ANON_ARGS[0];

 ptr = 0;
 foreach item ( dns_struct )
 {
  if ( ptr >= strlen(p) ) return NULL;
  ret[item] = getword(blob:p, pos:ptr);
  ptr += 2;
 }

 foreach item ( make_list("q", "an_rr", "au_rr", "ad_rr") )
 {
  for ( n = 0 ; n < ret[item] ; n ++ )
  {
   t = '';
   cur = item + "_data_" + n;
   while ( TRUE )
   {
    if ( ptr >= strlen(p) ) return ret;
    m = ord(p[ptr]);
    if ( (m & 0xc0) == 0xc0 ) # Compression
     {
      if ( strlen(t) ) t += ".";
      t += dns_comp_get(str:p, offset:ptr);
      ptr ++;
      m  = 0;
     }

    if ( m == 0 ) {
		ptr ++;
		ret[cur + "_name"] = t;
		if ( ptr + 2 >= strlen(p) ) break;
		ret[cur + "_type"] = getword(blob:p, pos:ptr);
		ptr += 2;
		if ( ptr + 2 >= strlen(p) ) break;
		ret[cur + "_class"] = getword(blob:p, pos:ptr);
		ptr += 2;
		if ( item != "q" )
		{
		 if ( ptr >= strlen(p) ) break;
		 ret[cur + "_ttl"] = getdword(blob:p, pos:ptr);
		 ptr += 4;
		 if ( ptr + 4>= strlen(p) ) break;
		 l = getword(blob:p, pos:ptr);
		 ptr += 2;
		 ret[cur + "_data"] = substr(p, ptr, ptr + l - 1);
		 ret[cur + "_data_offset"] = ptr;
		 ptr += l;
		}
		t = NULL;
		break;   
	}
    else {
	 if ( t ) t += ".";
	 else offset = ptr;

	 ptr ++;
	 t += substr(p, ptr,ptr +  m - 1);
	 ptr = ptr + m;
	}
    }
  }
 }

 return ret;
}
