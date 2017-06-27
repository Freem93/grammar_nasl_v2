#TRUSTED 51b8c869923cbe73f1e84fc7f2816f05cb3485fb46275f1741d71ce997d915ae89569e06157000b6bea9217c8896e776e0783b379f1e6d89db539f5369a91b6fbee0c7aca7e281dabe39d843023431b3540840f3274a7e70ee749b9f2434f1e0f30e7235140378aea1cea679d29ba8434276e021b9f8cfd24970b181254dd72674b45d25f10dd77afd660059793838d2ee298c2567fc63f609102d0e8746584098206e435978ed693477e9b158ff74ab714c77df2859143342c73af2291c08f44c99955815b71a7f5395ab5899c0cf1923bd626f40cf00ec7b61cbc1d3d40ebea70e51780ff231efd035e71494b23c12e3c74aa19d9bcae879fe0a4ed75634f51a7b88fcff22c248c5a7be0e4ed567e6d051acf3f8bcbb7984670c762be215218a026a717863aa9d5684cb59a8acb57e3a613b5c542405e66f5e20af727472f4c0877a0a9fe3055ade89762e0597992338209d838421b704ee765f134a37c0e526aac102389cb6efb27d48c5b31fe42585f32800e09283be086e8af1f527ee3a59216ca168ee31e458d6628ac161bbbd0cda069f12b7086a65e024f9889babb8b96efad659312b526ea1173de49bd03972d7cb925b75e0e04d71101587685c4ac53144ae548ec4da10920cccba7264d8fb8ca24d2f063765bb6b182572b69592cc1849bae78f6202096684e6235afff2a03a7b1e5fbe759a8436f69a864d8cac
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(23971);
 script_version("1.13");
 script_set_attribute(attribute:"plugin_modification_date", value:"2011/03/21"); 

 script_name(english:"Host Logical Network Segregation Weakness");
 script_summary(english:"Performs an ARP who-is on the remote host");
 
 script_set_attribute(attribute:"synopsis", value:
"The physical network is set up in a potentially insecure way." );
 script_set_attribute(attribute:"description", value:
"The remote host is on a different logical network than the
Nessus scanner. However, it is on the same physical subnet.

An attacker connecting from the same network as your Nessus
scanner could reconfigure his system to force it to belong
to the subnet of the remote host.

This may allow an attacker to bypass network filtering between
the two subnets." );
 script_set_attribute(attribute:"solution", value:
"Use VLANs to separate different logical networks." );
 script_set_attribute(attribute:"risk_factor", value:"Low" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/03");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");
 exit(0);
}


#


# ByteFunc included here
BYTE_ORDER_BIG_ENDIAN  		= 1;
BYTE_ORDER_LITTLE_ENDIAN 	= 2;

ByteOrder = BYTE_ORDER_BIG_ENDIAN;

function set_byte_order()
{
 ByteOrder = _FCT_ANON_ARGS[0];
}

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

 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
 	return  raw_string((l >> 8) & 0xFF, l & 0xFF);
 else
 	return  raw_string(l & 0xff, (l >> 8) & 0xff);
}


function mkdword()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];

 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
	 return  raw_string( (l >> 24 ) & 0xff,
		     	     (l >> 16 ) & 0xff,
		     	     (l >>  8 ) & 0xff,
		     	     (l)   & 0xff);
 else
	 return  raw_string( l & 0xff,
		     	    (l >> 8) & 0xff,
		            (l >> 16) & 0xff,
		            (l >> 24)   & 0xff);
}


function getdword(blob, pos)
{
 local_var l, s;
 if ( strlen(blob) < pos + 4 )
	return NULL;

 s = substr(blob, pos, pos + 3);
 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
  return ord(s[0]) << 24 | ord(s[1]) << 16 | ord(s[2]) << 8 | ord(s[3]);
 else
  return ord(s[0]) | ord(s[1]) << 8 | ord(s[2]) << 16 | ord(s[3]) << 24;
}

function getword(blob, pos)
{
 local_var l, s;
 if ( strlen(blob) < pos + 2 )
	return NULL;
 s = substr(blob, pos, pos + 1);
 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
  return ord(s[0]) << 8 | ord(s[1]);
 else
  return ord(s[0]) | ord(s[1]) << 8;
}

function getbyte(blob, pos)
{
 local_var l, s;
 if ( strlen(blob) < pos + 1 )
	return NULL;
 s = substr(blob, pos, pos);
 return ord(s[0]);
}




function mkpad()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];
 return crap(data:raw_string(0), length:l);
}





function mkipaddr()
{
 local_var ip;
 local_var str;

 ip = _FCT_ANON_ARGS[0];
 str = split(ip, sep:'.', keep:FALSE);
 return raw_string(int(str[0]), int(str[1]), int(str[2]), int(str[3])); 
}


function is_class_b(a,b)
{
 local_var aa, ab;
 local_var i;

 aa = split(a, sep:'.', keep:FALSE);
 ab = split(b, sep:'.', keep:FALSE);
 
 for ( i = 0 ; i < 4 ; i ++ )
 {
   if ( aa[i] != ab[i] ) break;
 }

 if ( i < 2 ) return FALSE;
 else return TRUE;
}


function arp_ping()
{
 local_var broadcast, macaddr, arp, ethernet, i, r, srcip, dstmac;

 broadcast = crap(data:raw_string(0xff), length:6);
 macaddr   = get_local_mac_addr();

 if ( ! macaddr ) return 0;  # Not an ethernet interface

 arp       = mkword(0x0806); 
 ethernet = broadcast + macaddr + arp;
 arp      = ethernet +              			# Ethernet
           mkword(0x0001) +        			# Hardware Type
           mkword(0x0800) +        			# Protocol Type
           mkbyte(0x06)   +        			# Hardware Size
           mkbyte(0x04)   +        			# Protocol Size
           mkword(0x0001) +        			# Opcode (Request)
           macaddr        +        			# Sender mac addr
           mkipaddr(this_host()) + 			# Sender IP addr
           crap(data:raw_string(0), length:6) + 	# Target Mac Addr
           mkipaddr(get_host_ip());

 for ( i = 0 ; i < 2 ; i ++ )
 {
  r = inject_packet(packet:arp, filter:"arp and arp[7] = 2 and src host " + get_host_ip(), timeout:1);
  if ( ! r || strlen(r) <= 31 ) continue;
  srcip = substr(r, 28, 31);
  if ( srcip == mkipaddr(get_host_ip() ) )
   {
    dstmac = substr(r, 6, 11);
    dstmac = strcat(hexstr(dstmac[0]), ":",
	            hexstr(dstmac[1]), ":",
		    hexstr(dstmac[2]), ":",
		    hexstr(dstmac[3]), ":",
		    hexstr(dstmac[4]), ":",
		    hexstr(dstmac[5]));
    return dstmac;
   }
  }
}

# Nessus 3 only
if ( ! defined_func("inject_packet") ) exit(0);
if ( ! isnull(get_gw_mac_addr()) ) exit(0);

# If the target is officially in the same subnet, exit
if ( islocalnet() || TARGET_IS_IPV6 ) exit(0);

opt = get_kb_item("global_settings/thorough_tests");
if (! opt || "yes" >!< opt  )
	# If the target is not at least in the same class B, exit
	if ( ! is_class_b(a:this_host(), b:get_host_ip() ) ) exit(0);



if ( mac = arp_ping() )
{
 if ( mac == get_gw_mac_addr() ) exit(0); # Arp proxy
 replace_kb_item(name:"ARP/mac_addr", value:mac);
 security_note(port:0,extra:"The MAC address of the remote host is " + mac );
}
