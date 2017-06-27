#TRUSTED 2bfe5aa9d6ff38bedaa738bdbb16eb2bdc1cd2619c2cc4beb00b30119edb10b775ee032a575ba196b20d8e2d581d2dacb42512dc2d84d5209cdc9012b33e1005621b3fe59452586b10217bd44d8bb3528f7cc25ae4e7bd0959299400525e383c9cb00d1e23c611932edb9258f798b59873eeb2137aa12ba611822c79717c62aa7c37029c5f0a9f4bd4c1cf220e873e92706013ada9ce852e004f17c104231878a520c87bb790cec8bb88b00d5e4565622584b8fb72af95cd579fcd0b94f32fbdd781b0e28a9c2c67819207d4d43efa76e9972991a715a202ccd9f2147bb93c1d47f666b0d6be056c95ff8df7833b6aaa1afdc2b8ab24374f9549dbe1f2d1a54872166a87affb3c2839ab8d0d6e059351061644acb09ad9bca89d5095a91c55ed089d375773fabb8321c0dfd2be7b85b6aca984973db46af6e28400901075780589b83042ed69033defc0e376392d2ecab68e758155da3d883c24a9839d61abe9d7943020cf8981e471b6b1b7bab929ff22996f5f4cdd358440cd9e7688b678ac185942755593d17cf73d1662fb136c6e54ebbcc4fc6138200b2b7095744213a1aa3c40942fa0c54277c403fc55296627b5ef7b51e5322d60f632942eeb0b5d402d8b87680fad5886f0b5ebc0361e0de685df1c3cf0de039a651b191383c090777d4e0747749b266b0ed51b7269538cf13cb1aa93cd9c1543e5102cf986752fe4
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("get_local_mac_addr")) exit(0);
if (! defined_func("inject_packet")) exit(0);
include("compat.inc");

if(description)
{
 script_id(35713);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2011/03/17");

 script_name(english: "Scan for UPnP hosts (multicast)");
 script_summary(english: "Multicast a UPnP NOTIFY multicast");

 script_set_attribute(attribute:"synopsis", value:"This machine is a UPnP client.");
 script_set_attribute(attribute:"description", value:
"This machine answered to a multicast UPnP NOTIFY packet by trying to 
fetch the XML description that Nessus advertised.");
 script_set_attribute(attribute:"solution", value: "n/a");
 script_set_attribute(attribute:"risk_factor", value: "None");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/19");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");
 script_family(english: "Service detection");
 script_exclude_keys("/tmp/UDP/1900/closed");
 exit(0);
}

global_var debug_level;
include('misc_func.inc');
include('byte_func.inc');

if (! get_kb_item("Host/udp_scanned") &&
    ! get_kb_item("global_settings/thorough_tests") ) exit(0);

if ( TARGET_IS_IPV6 ) exit(0);	# TBD

if ( safe_checks() ) exit(0); # Switch issues
if (islocalhost()) exit(0);
if (!islocalnet())exit(0);
if (! get_udp_port_state(1900) || get_kb_item("/tmp/UDP/1900/closed")) exit(0);
if (! service_is_unknown(port: 1900, ipproto: "udp")) exit(0);

myaddr = this_host();
dstaddr = get_host_ip();
returnport = rand() % 32768 + 32768;

data = strcat(
'NOTIFY * HTTP/1.1\r\n',
'HOST: 239.255.255.250:1900\r\n',
'CACHE-CONTROL: max-age=1800\r\n',
'LOCATION: http://', myaddr, ':', returnport, '/gatedesc.xml\r\n',
'NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n',
'NTS: ssdp:alive\r\n',
'SERVER: Linux/2.6.26-hardened-r9, UPnP/1.0, Portable SDK for UPnP devices/1.6.6\r\n',
'X-User-Agent: redsonic\r\n',
'USN: uuid:75802409-bccb-40e7-8e6c-fa095ecce13e::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n',
'\r\n' );

len = strlen(data);

ip = forge_ip_packet(ip_hl: 5, ip_v: 4, ip_tos: 0, ip_len: 20,
   ip_id: rand(), ip_off: 0, ip_ttl: 64, ip_p: IPPROTO_UDP,
   ip_src: myaddr, ip_dst: '239.255.255.250');

udp = forge_udp_packet(ip: ip, uh_sport: rand() % 32768 + 32768, uh_dport: 1900,
 uh_ulen :8 + len, data: data);
if ( defined_func("datalink") ) 
{
 if ( datalink() != DLT_EN10MB ) exit(0);
}

macaddr   = get_local_mac_addr();

ethernet = '\x01\x00\x5E\x7F\xFF\xFA'	# Multicast address
	 + macaddr
	 + mkword(0x0800)		# Protocol = IPv4
	 + udp;
filter = strcat("tcp and src ", dstaddr, " and dst port ", returnport);

for (i = 0; i < 60; i ++)
{
  r = inject_packet(packet: ethernet, filter:filter, timeout: 1);
  if (strlen(r) > 14 + 20 + 20)
  {
    flags = get_tcp_element(tcp: substr(r, 14), element:"th_flags");
    if (flags & TH_SYN)
    {
       security_note(port:1900,protocol:"udp");
       register_service(port: 1900, proto: "upnp-client", ipproto: "udp");
    }
    exit(0);     
  }
}
