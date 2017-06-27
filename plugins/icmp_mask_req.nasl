#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10113);
 script_version ("$Revision: 1.36 $");

 script_cve_id("CVE-1999-0524");
 script_osvdb_id(95);

 script_name(english:"ICMP Netmask Request Information Disclosure");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host answers to an ICMP_MASKREQ query and responds with its
netmask.  An attacker can use this information to understand how your
network is set up and how routing is done.  This may help him to
bypass your filters." );
 script_set_attribute(attribute:"solution", value:
"Reconfigure the remote host so that it does not answer to those
requests.  Set up filters that deny ICMP packets of type 17." );
 script_set_attribute(attribute:"risk_factor", value:
"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/07/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "1995/01/01");
 script_cwe_id(200);
 script_cvs_date("$Date: 2011/11/15 14:05:41 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Sends an ICMP_MASKREQ");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2011 Tenable Network Security, Inc.");
 script_family(english:"General");
 
 exit(0);
}

#
# The script code starts here
#

if ( TARGET_IS_IPV6 ) exit(0);
if ( islocalhost() ) exit(0);

ip = forge_ip_packet(ip_hl:5, ip_v:4,   ip_off:0,
                     ip_id:9, ip_tos:0, ip_p : IPPROTO_ICMP,
                     ip_len : 20, ip_src : this_host(),
                     ip_ttl : 255);

icmp = forge_icmp_packet(ip:ip,icmp_type : 17, icmp_code:0,
                          icmp_seq : 1, icmp_id : 1, data:raw_string(0xFF, 0xFF, 0xFF, 0xFF));

filter = string("icmp and src host ", get_host_ip(), " and dst host ", this_host(), " and icmp[0:1] = 18");
for(i=0;i<3;i++)
{
 r = send_packet(icmp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:3);
 if(!isnull(r))
 {
  type = get_icmp_element(icmp:r, element:"icmp_type");
  if(type == 18){
	data = get_icmp_element(icmp:r, element:"data");
	if ( strlen(data) != 4 ) exit(0);
	mask = "";
	for(i=0;i<4;i=i+1)
	{
   	 mask = string(mask, ord(data[i]));
	 if(i<3)mask = string(mask, ".");
	}

	report = string(
	 "  Netmask : ", mask, "\n"
	);
	security_note(protocol:"icmp", port:0, extra:report);
	set_kb_item(name: 'icmp/mask_req', value: TRUE);
  }
  exit(0);
 }
}
