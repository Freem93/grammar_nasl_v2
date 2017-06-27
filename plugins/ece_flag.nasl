#

# Changes by Tenable:
# - Revised plugin title, tweaked output formatting, changed family (9/1/09)

include("compat.inc");

if (description)
{
 script_id(12118);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2014/05/25 23:51:31 $");

 script_cve_id("CVE-2001-0183");
 script_bugtraq_id(2293);
 script_osvdb_id(1743);

 script_name(english:"Multiple BSD ipfw / ip6fw ECE Bit Filtering Evasion");
 script_summary(english:"Firewall ECE-bit bypass");

 script_set_attribute(attribute:"synopsis", value:"Firewalling rules may be circumvented.");
 script_set_attribute(attribute:"description", value:
"The remote host seems vulnerable to a bug wherein a remote attacker
can circumvent the firewall by setting the ECE bit within the TCP
flags field. At least one firewall (ipfw) is known to exhibit this
sort of behavior.

Known vulnerable systems include all FreeBSD 3.x ,4.x, 3.5-STABLE, and
4.2-STABLE.");
 script_set_attribute(attribute:"solution", value:
"If you are running FreeBSD 3.X, 4.x, 3.5-STABLE, 4.2-STABLE, upgrade
your firewall. If you are not running FreeBSD, contact your firewall
vendor for a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/01/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/03/30");

script_set_attribute(attribute:"potential_vulnerability", value:"true");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Firewalls");
 script_copyright(english:"This script is Copyright (C) 2004-2014 Andrey I. Zakharov and John Lampe");

 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include('global_settings.inc');

if ( TARGET_IS_IPV6 ) exit(0);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( islocalnet() || islocalhost() ) exit(0);


# start script
sport= (rand() % 64511) + 1024;
ipid = 1234;
myack = 0xFF67;
init_seq = 538;


# so, we need a list of commonly open, yet firewalled ports...
port[0] = 22;
port[1] = 111;
port[2] = 1025;
port[3] = 139;
port[4] = 3389;
port[5] = 23;



for (i=0; port[i]; i++) {
    if ( get_port_state(port[i]) ) continue; # Port is open
    reply=NULL;
    sport++;
    filter = string("src port ", port[i], " and src host ", get_host_ip(), " and dst port ", sport);

    # STEP 1:  Send a Naked SYN packet

    ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0,ip_off:0,ip_len:20,
                         ip_p:IPPROTO_TCP, ip_id:ipid, ip_ttl:0x40,
                         ip_src:this_host());


    tcp = forge_tcp_packet(ip:ip, th_sport:sport, th_dport:port[i],
                          th_flags:0x02, th_seq:init_seq,th_ack:myack,
                          th_x2:0, th_off:5, th_win:2048, th_urp:0);



    for ( j = 0 ; j < 3 ; j ++ )
    {
    	reply =  send_packet(tcp,
			pcap_active : TRUE,
                        pcap_filter : filter,
                        pcap_timeout : 1);
    	if ( reply ) break;
    }


    # STEP 2:  If we don't get a response back from STEP 1,
    # we will send a SYN+ECE to port

    if (! reply)
    {
	     sport++;
    	     filter = string("src port ", port[i], " and src host ", get_host_ip(), " and dst port ", sport);
             ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0,ip_off:0,ip_len:20,
                         ip_p:IPPROTO_TCP, ip_id:ipid, ip_ttl:0x40,
                         ip_src:this_host());


             tcp = forge_tcp_packet(ip:ip, th_sport:sport, th_dport:port[i],
                          th_flags:0x42, th_seq:init_seq,th_ack:myack,
                          th_x2:0, th_off:5, th_win:2048, th_urp:0);


	     for ( j = 0; j < 3 ; j ++ )
	     {
             	reply =  send_packet(pcap_active : TRUE,
                        pcap_filter : filter,
                        pcap_timeout : 1,
                        tcp);
		if (reply) break;
	     }


             if (reply)
	     {
                 flags = get_tcp_element(tcp:reply, element:"th_flags");
                 if (flags & TH_ACK) security_hole(port);
             }
    }


}

exit(0);




