#TRUSTED 559dfdfe862ee11faa1bab6128d3bd4413f264c66d8abdb1a64fae0a6264266ca5a596f2f6339407faef4a40bc8b07f1acd6b67fe8ad3d3ab9944e404eca491bdb6e7ef8b4328e80466c0e8d0fde27b5d3c53361f383d9916576d94633440780019d84ac3a6df790ad08a3edcbe595cadaefc175109783b3cb1c6aff1c5e2151a6f359919a08752f486f28c1bddb3b734ee55bcc4b090ae75609cdeddcc67495db9aa8d5797578118163bfd960c701873deb6b39ec3a163c45475ec980785bc1b3dbfb85d8f53d3a6cbc9e264d3237485835404c424aa07b8b9cea6f03d8caa5066d780150f38d8cd88124f9c6bf1277b7f012a70d953145384fbdfcbd114befe6655f9ebd6cc32ce7afcee5509623bad2689840f4d93340740b14d36169c8b9d60e9be431e5ba7a3de3c8eff5642120428a37c788b40b01a822c41ffe183b476315dd5d3952fc893ca5d8d40ba697b248dff4626347ac03d72286c7fb57492c5ffe186f3e39157768f7d6f9fa929acd756f8d7a02901718419a270d28bcd5f7af3d53b86e401e45375699f450e3fbc19f71e6dec12bb8fc0f9b9631416fde67d193cfd20ad93912c994d16f71d1d95eb5e7dd455cd0bd2e8fa28dc95d102c6fca5e0ca6b618b0b6170ca0871bbb76525384bee717a35f9a81b4046afa7e5ccae03c1fb44b2da7a2efa8b5b754a81f5e075f6afc2b9813e0c3ba83fc8417221c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(24904);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2011/03/21"); 

 script_name(english:"Link Layer Topology Discovery (LLTD) Detection");
 script_summary(english:"Performs a LLTD HELO query to the remote host");

 script_set_attribute(attribute:"synopsis", value:
"The remote host speaks the LLTD protocol" );
 script_set_attribute(attribute:"description", value:
"The remote host responds to the LLTD (Link Layer Topology Discovery)
protocol.

This protocol can be used to enumerate the IPv4 and IPv6 addresses
of a remote host, its name, the characteristics of the physical layer it 
is connected to, as well as the topology of the network, etc...

This plugin attempts to extract the IP addresses of the remote host
as well as the physical layer it is connected to the network with." );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/whdc/Rally/LLTD-spec.mspx" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/30");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
 family["english"] = "General";
 script_family(english:family["english"]);
 exit(0);
}




# Switches issues
if ( safe_checks() ) exit(0); 

if ( ! defined_func("inject_packet") ) exit(0);
if (! islocalnet() ) exit(0); 


# Byte_func.inc


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





TLV_EOP 		= 0;
TLV_HostID 		= 1;
TLV_PhysMedium 		= 3;
TLV_IPv4_Address 	= 7;
TLV_IPv6_Address 	= 8;
TLV_PerfCounter 	= 10;
TLV_LinkSpeed 		= 12;
TLV_MachName  		= 15;

ifType[1] = "other";
ifType[2] = "regular1822";
ifType[3] = "hdh1822";
ifType[4] = "ddnX25";
ifType[5] = "rfc877x25";
ifType[6] = "ethernetCsmacd";
ifType[7] = "iso88023Csmacd";
ifType[8] = "iso88024TokenBus";
ifType[9] = "iso88025TokenRing";
ifType[10] = "iso88026Man";
ifType[11] = "starLan";
ifType[12] = "proteon10Mbit";
ifType[13] = "proteon80Mbit";
ifType[14] = "hyperchannel";
ifType[15] = "fddi";
ifType[16] = "lapb";
ifType[17] = "sdlc";
ifType[18] = "ds1";
ifType[19] = "e1";
ifType[20] = "basicISDN";
ifType[21] = "primaryISDN";
ifType[22] = "propPointToPointSerial";
ifType[23] = "ppp";
ifType[24] = "softwareLoopback";
ifType[25] = "eon";
ifType[26] = "ethernet3Mbit";
ifType[27] = "nsip";
ifType[28] = "slip";
ifType[29] = "ultra";
ifType[30] = "ds3";
ifType[31] = "sip";
ifType[32] = "frameRelay";
ifType[33] = "rs232";
ifType[34] = "para";
ifType[35] = "arcnet";
ifType[36] = "arcnetPlus";
ifType[37] = "atm";
ifType[38] = "miox25";
ifType[39] = "sonet";
ifType[40] = "x25ple";
ifType[41] = "iso88022llc";
ifType[42] = "localTalk";
ifType[43] = "smdsDxi";
ifType[44] = "frameRelayService";
ifType[45] = "v35";
ifType[46] = "hssi";
ifType[47] = "hippi";
ifType[48] = "modem";
ifType[49] = "aal5";
ifType[50] = "sonetPath";
ifType[51] = "sonetVT";
ifType[52] = "smdsIcip";
ifType[53] = "propVirtual";
ifType[54] = "propMultiplexor";
ifType[55] = "ieee80212";
ifType[56] = "fibreChannel";
ifType[57] = "hippiInterface";
ifType[58] = "frameRelayInterconnect";
ifType[59] = "aflane8023";
ifType[60] = "aflane8025";
ifType[61] = "cctEmul";
ifType[62] = "fastEther";
ifType[63] = "isdn";
ifType[64] = "v11";
ifType[65] = "v36";
ifType[66] = "g703at64k";
ifType[67] = "g703at2mb";
ifType[68] = "qllc";
ifType[69] = "fastEtherFX";
ifType[70] = "channel";
ifType[71] = "ieee80211";
ifType[72] = "ibm370parChan";
ifType[73] = "escon";
ifType[74] = "dlsw";
ifType[75] = "isdns";
ifType[76] = "isdnu";
ifType[77] = "lapd";
ifType[78] = "ipSwitch";
ifType[79] = "rsrb";
ifType[80] = "atmLogical";
ifType[81] = "ds0";
ifType[82] = "ds0Bundle";
ifType[83] = "bsc";
ifType[84] = "async";
ifType[85] = "cnr";
ifType[86] = "iso88025Dtr";
ifType[87] = "eplrs";
ifType[88] = "arap";
ifType[89] = "propCnls";
ifType[90] = "hostPad";
ifType[91] = "termPad";
ifType[92] = "frameRelayMPI";
ifType[93] = "x213";
ifType[94] = "adsl";
ifType[95] = "radsl";
ifType[96] = "sdsl";
ifType[97] = "vdsl";
ifType[98] = "iso88025CRFPInt";
ifType[99] = "myrinet";
ifType[100] = "voiceEM";
ifType[101] = "voiceFXO";
ifType[102] = "voiceFXS";
ifType[103] = "voiceEncap";
ifType[104] = "voiceOverIp";
ifType[105] = "atmDxi";
ifType[106] = "atmFuni";
ifType[107] = "atmIma";
ifType[108] = "pppMultilinkBundle";
ifType[109] = "ipOverCdlc";
ifType[110] = "ipOverClaw";
ifType[111] = "stackToStack";
ifType[112] = "virtualIpAddress";
ifType[113] = "mpc";
ifType[114] = "ipOverAtm";
ifType[115] = "iso88025Fiber";
ifType[116] = "tdlc";
ifType[117] = "gigabitEthernet";
ifType[118] = "hdlc";
ifType[119] = "lapf";
ifType[120] = "v37";
ifType[121] = "x25mlp";
ifType[122] = "x25huntGroup";
ifType[123] = "trasnpHdlc";
ifType[124] = "interleave";
ifType[125] = "fast";
ifType[126] = "ip";
ifType[127] = "docsCableMaclayer";
ifType[128] = "docsCableDownstream";
ifType[129] = "docsCableUpstream";
ifType[130] = "a12MppSwitch";
ifType[131] = "tunnel";
ifType[132] = "coffee";
ifType[133] = "ces";
ifType[134] = "atmSubInterface";
ifType[135] = "l2vlan";
ifType[136] = "l3ipvlan";
ifType[137] = "l3ipxvlan";
ifType[138] = "digitalPowerline";
ifType[139] = "mediaMailOverIp";
ifType[140] = "dtm";
ifType[141] = "dcn";
ifType[142] = "ipForward";
ifType[143] = "msdsl";
ifType[144] = "ieee1394";
ifType[145] = "if-gsn";
ifType[146] = "dvbRccMacLayer";
ifType[147] = "dvbRccDownstream";
ifType[148] = "dvbRccUpstream";
ifType[149] = "atmVirtual";
ifType[150] = "mplsTunnel";
ifType[151] = "srp";
ifType[152] = "voiceOverAtm";
ifType[153] = "voiceOverFrameRelay";
ifType[154] = "idsl";
ifType[155] = "compositeLink";
ifType[156] = "ss7SigLink";
ifType[157] = "propWirelessP2P";
ifType[158] = "frForward";
ifType[159] = "rfc1483";
ifType[160] = "usb";
ifType[161] = "ieee8023adLag";
ifType[162] = "bgppolicyaccounting";
ifType[163] = "frf16MfrBundle";
ifType[164] = "h323Gatekeeper";
ifType[165] = "h323Proxy";
ifType[166] = "mpls";
ifType[167] = "mfSigLink";
ifType[168] = "hdsl2";
ifType[169] = "shdsl";
ifType[170] = "ds1FDL";
ifType[171] = "pos";
ifType[172] = "dvbAsiIn";
ifType[173] = "dvbAsiOut";
ifType[174] = "plc";
ifType[175] = "nfas";
ifType[176] = "tr008";
ifType[177] = "gr303RDT";
ifType[178] = "gr303IDT";
ifType[179] = "isup";
ifType[180] = "propDocsWirelessMaclayer";
ifType[181] = "propDocsWirelessDownstream";
ifType[182] = "propDocsWirelessUpstream";
ifType[183] = "hiperlan2";
ifType[184] = "propBWAp2Mp";
ifType[185] = "sonetOverheadChannel";
ifType[186] = "digitalWrapperOverheadChannel";
ifType[187] = "aal2";
ifType[188] = "radioMAC";
ifType[189] = "atmRadio";
ifType[190] = "imt";
ifType[191] = "mvl";
ifType[192] = "reachDSL";
ifType[193] = "frDlciEndPt";
ifType[194] = "atmVciEndPt";
ifType[195] = "opticalChannel";
ifType[196] = "opticalTransport";
ifType[197] = "propAtm";
ifType[198] = "voiceOverCable";
ifType[199] = "infiniband";
ifType[200] = "teLink";
ifType[201] = "q2931";
ifType[202] = "virtualTg";
ifType[203] = "sipTg";
ifType[204] = "sipSig";
ifType[205] = "docsCableUpstreamChannel";
ifType[206] = "econet";
ifType[207] = "pon155";
ifType[208] = "pon622";
ifType[209] = "bridge";
ifType[210] = "linegroup";
ifType[211] = "voiceEMFGD";
ifType[212] = "voiceFGDEANA";
ifType[213] = "voiceDID";
ifType[214] = "mpegTransport";
ifType[215] = "sixToFour";
ifType[216] = "gtp";
ifType[217] = "pdnEtherLoop1";
ifType[218] = "pdnEtherLoop2";
ifType[219] = "opticalChannelGroup";
ifType[220] = "homepna";
ifType[221] = "gfp";
ifType[222] = "ciscoISLvlan";
ifType[223] = "actelisMetaLOOP";
ifType[224] = "fcipLink";
ifType[225] = "rpr";
ifType[226] = "qam";
ifType[227] = "lmp";
ifType[228] = "cblVectaStar";
ifType[229] = "docsCableMCmtsDownstream";
ifType[230] = "adsl2";
ifType[231] = "macSecControlledIF";
ifType[232] = "macSecUncontrolledIF";
ifType[233] = "aviciOpticalEther";
ifType[234] = "atmbond";
ifType[235] = "voiceFGDOS";
ifType[236] = "mocaVersion1";
ifType[237] = "ieee80216WMAN";
ifType[238] = "adsl2plus";
ifType[239] = "dvbRcsMacLayer";
ifType[240] = "dvbTdm";
ifType[241] = "dvbRcsTdma";
ifType[242] = "x86Laps";


mac_addr = get_local_mac_addr();
if ( ! mac_addr ) exit(0);
remote   = get_gw_mac_addr();
if ( ! remote ) exit(0);
broadcast = crap(data:mkbyte(0xff), length:6);

ascii_remote = hexstr(remote[0]) + ":" +
               hexstr(remote[1]) + ":" +
               hexstr(remote[2]) + ":" +
               hexstr(remote[3]) + ":" +
               hexstr(remote[4]) + ":" +
               hexstr(remote[5]);



function raw_to_ipv4()
{
 local_var i;
 local_var ip;
 local_var ret;

 ip = _FCT_ANON_ARGS[0];
 if ( strlen(ip) != 4 ) return NULL;
 for ( i = 0 ; i < 4 ; i ++ )
 {
  if ( ret ) ret += ".";
  ret += ord(ip[i]);
 }

 return ret;
}


function raw_to_ipv6()
{
 local_var i;
 local_var ip;
 local_var ret, ret0;
 local_var idx, n;
 local_var long;

 ip = _FCT_ANON_ARGS[0];
 if ( strlen(ip) != 16 ) return NULL;
 for ( i = 0 ; i < 16 ; i += 2 )
 {
    if ( ret ) ret += ":";
    ret += hexstr(raw_string(ord(ip[i]) , ord(ip[i+1])));
 }

 long = NULL;
 n = idx = stridx(ret, ":0000:");
 if ( idx > 0 )
 {
  while ( ret[idx] == ":" || ret[idx] == "0" )
	{
	 long += ret[idx];
	 idx ++;  
	}
  ret0 = ret;
  ret = substr(ret0, 0, n - 1);
  ret += "::";
  ret += substr(ret0, idx, strlen(ret0) - 1); 
 }
 
 return ret;
}


ethernet = remote +
	   mac_addr +
	   mkword(0x88d9);


reset = ethernet +
	mkbyte(1) +
	mkbyte(1) +
	mkbyte(0) +	# Reserved
	mkbyte(0x08) +
	broadcast +
	get_local_mac_addr() +
	mkword(0);


discover = ethernet +
	   mkbyte(1) +
	   mkbyte(1) +
	   mkbyte(0) +
	   mkbyte(0) +
	   broadcast +
	   get_local_mac_addr() +
	   mkword(rand() % 65535);


	 






inject_packet(packet:reset);
sleep(1);
report = NULL;
r = inject_packet(packet:discover, filter:"ether proto 0x88d9 and ether src host "  + ascii_remote, timeout:3);
if ( r ) 
{
 if ( getword(blob:r, pos:12) != 0x88d9 ) exit(0);
 r = substr(r, 6 + 6 + 2, strlen(r) - 1);
 if ( ord(r[0]) != 1 ) exit(0); # Make sure this is version 1
 if ( ord(r[1]) != 1 ) exit(0); # Make sure this is a discover packet
 if ( ord(r[3]) != 1 ) exit(0); # Make sure this is a hello packet
 r = substr(r, 4 + 12 + 1 + 6 + 6 + 3, strlen(r) - 1);  
 idx = 0;
 len = strlen(r);
 while ( idx < len )
 {
  code = ord(r[idx]);
  if ( code == 0 ) break;
  length = ord(r[idx+1]);
  if ( length ) value  = substr(r, idx + 2, idx + 2 + length - 1);
  else value = NULL;

  if ( code == TLV_EOP ) break;
  if ( code == TLV_HostID && value )
	  report += ' - Host ID : ' + hexstr(value) + '\n';
  if ( code == TLV_IPv4_Address )
	{
	  ipv4 = raw_to_ipv4(value);
	  if ( ipv4 ) report += ' - IPv4 address : ' + ipv4 + '\n';
	}
  if ( code == TLV_PhysMedium )
	{
	 type = getdword(blob:value, pos:0);
	 if ( type > 0 && type < max_index(ifType) )
	   report += " - Physical medium : " + ifType[type] + '\n'; 
	}
  if ( code == TLV_LinkSpeed)
	{
	 value = getdword(blob:value, pos:0);
	 unit = "b/s";
	 if ( value >= 10 ) { value = value / 10;  unit  = "Kb/s"; }
	 if ( value >= 1000 ) { value /= 1000; unit = "Mb/s"; } 
	 if ( value >= 1000 ) { value /= 1000; unit = "Gb/s"; }
	 if ( value > 0 ) 
	   report += " - Link speed : " + value + " " + unit + '\n'; 
	}
  if ( code == TLV_IPv6_Address )
	 {
	  ipv6 = raw_to_ipv6(value);
	  if ( ipv6 ) report += ' - IPv6 address : ' + ipv6 + '\n';
	 }
  if ( code == TLV_MachName )
	  report += ' - Machine name : ' + str_replace(find:mkbyte(0), replace:"", string:value) + '\n';
	
  idx = idx + 2 + length;
 }

 if ( report )
	security_note(port:0, extra:'\n' + report);
}
