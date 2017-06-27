#
# This script was written by John Lampe...j_lampe@bellsouth.net
#

# Changes by Tenable:
# - Revised plugin title (9/8/09)


include("compat.inc");

if(description)
{
 script_id(10829);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2014/05/09 18:59:10 $");
# script_cve_id("CVE-2001-0876");
# script_bugtraq_id(3723);
# script_xref(name:"OSVDB", value:"692");
 script_name(english: "UPnP Client Detection");

 script_set_attribute(attribute:"synopsis", value:
"This machine is a UPnP client." );
 script_set_attribute(attribute:"description", value:
"This machine answered to a unicast UPnP NOTIFY packet by trying to
fetch the XML description that Nessus advertised." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/12/29");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english: "UPnP scan");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2014 by John Lampe & Tenable Network Security, Inc.");
 script_family(english: "Service detection");
 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

if ( TARGET_IS_IPV6 ) exit(0);
if (islocalhost())exit(0);

if (! get_udp_port_state(1900)) exit(0);

#script based on eeye advisory Multiple Remote Windows XP/ME/98 Vulnerabilities

myaddr = this_host();
dstaddr = get_host_ip();
returnport = rand() % 32768 + 32768;

  mystring = string("NOTIFY * HTTP/1.1\r\n");
  mystring = mystring + string("HOST: ", "239.255.255.250" , ":1900\r\n");
  mystring = mystring + string("CACHE-CONTROL: max-age=10\r\n");
  mystring = mystring + string("LOCATION: http://" , myaddr, ":" , returnport , "/foo.xms\r\n");
  mystring = mystring + string("NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n");
  mystring = mystring + string("NTS: ssdp:alive\r\n");
  mystring = mystring + string("SERVER: NESSUS/2001 UPnP/1.0 product/1.1\r\n");
  mystring = mystring + string("USN: uuid:NESSUS\r\n\r\n");
  len = strlen(mystring);

  ippkt = forge_ip_packet(
        ip_hl   :5,
        ip_v    :4,
        ip_tos  :0,
        ip_len  :20,
        ip_id   :31337,
        ip_off  :0,
        ip_ttl  :64,
        ip_p    :IPPROTO_UDP,
        ip_src  :myaddr
        );


  udppacket = forge_udp_packet(
        ip      :ippkt,
        uh_sport: rand() % 32768 + 32768,
        uh_dport:1900,
        uh_ulen :8 + len,
        data    :mystring
        );

for (i = 0; i < 3; i ++)
{
  filter = strcat("src " , dstaddr , " and (icmp or (tcp and dst port ", returnport, " ))");
  r = send_packet(udppacket, pcap_active:TRUE, pcap_filter:filter, pcap_timeout: 5);
  if (strlen(r) > 20)
  {
    if (ord(r[9]) == 6)
    {
      flags = get_tcp_element(tcp:r, element:"th_flags");
      if (flags & TH_SYN)
      {
        security_note(port:1900,protocol:"udp");
	register_service(port: 1900, proto: "upnp-client", ipproto: "udp");
      }
      exit(0);     
    }
    else if (ord(r[9]) == 1)
    {
      hl = ord(r[0]) & 0xF; hl *= 4;
      if (strlen(r) >= hl + 8)
      {
        type = ord(r[hl + 0]);
        code = ord(r[hl + 1]);
	if (type == 3)
	{
	  if (code == 3)
	    set_kb_item(name: "/tmp/UDP/1900/closed", value: TRUE);
	  exit(0);
	}
      }
    }
  }
}

