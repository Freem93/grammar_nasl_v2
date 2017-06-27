#
# This script was written by John Lampe...j_lampe@bellsouth.net
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10796);
 script_version ("$Revision: 1.13 $");
 script_cvs_date("$Date: 2011/03/21 01:21:16 $");

 script_name(english:"LaBrea Tarpitted Host Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is fake." );
 script_set_attribute(attribute:"description", value:
"This script performs a Labrea tarpit scan, by sending a bogus ACK and 
ACK-windowprobe to a potential host.  It also sends a TCP SYN to test 
for non-persisting labrea machines." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/11/06");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"LaBrea scan");
 # ACT_SETTINGS would be better, but they are automatically enabled
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2011 by John Lampe");
 script_family(english:"General");
 exit(0);
}

#

include('global_settings.inc');
if ( TARGET_IS_IPV6 ) exit(0);

# Labrea only answers to TCP probes
if (get_kb_item('/tmp/ping/ICMP') || get_kb_item('/tmp/ping/UDP'))
{
 debug_print('Host answered to ICMP or UDP probes - cannot be "tar pitted"\n');
 exit(0);
}

src = this_host();
dst = get_host_ip();
sport=3133;
dport=rand() % 65535;
init_seq=2357;
init_ip_id = 1234;
filter = string("src port ", dport, " and src host ", dst);
myack = 0xFF67;
init_seq = 538;
init_ip_id = 12;
winsize = 100;
flags = 0;

debug_print(level: 2, 'sport=',sport, ' - dport=',dport,'\n');

# send two ACKs with a single byte as data (probe window)
# Labrea in persist mode will ACK the packet below after the initial
# "ARP-who has" timeout (defaults to 3 seconds, hence the 2 packets)

for (q=0; q<2; q = q + 1) {
    ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0,ip_off:0,ip_len:20,
                         ip_p:IPPROTO_TCP, ip_id:init_ip_id, ip_ttl:0x40,
                         ip_src:this_host());

    tcp = forge_tcp_packet(ip:ip, th_sport:sport, th_dport:dport,
                          th_flags:TH_ACK, th_seq:init_seq,th_ack:myack,
                          th_x2:0, th_off:5, th_win:2048, th_urp:0, data:"H");



    reply =  send_packet(pcap_active : TRUE,
                        pcap_filter : filter,
                        pcap_timeout : 3,
                        tcp);
}


if(!reply)exit(0);



winsize = get_tcp_element(tcp:reply, element:"th_win");
flags = get_tcp_element(tcp:reply, element:"th_flags");

# don't know when this would be true...but adding it nonetheless
if (flags & TH_RST) {
    exit(0);
}



if ( (winsize <= 10) && (flags & TH_ACK) ) {
      set_kb_item(name:"Host/dead", value:TRUE);
      exit(0);
}




# now handle LaBrea in non-persist mode

    winsize = 100;
    flags = 0;

    ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0,ip_off:0,ip_len:20,
                         ip_p:IPPROTO_TCP, ip_id:init_ip_id, ip_ttl:0x40,
                         ip_src:this_host());

    tcp = forge_tcp_packet(ip:ip, th_sport:sport, th_dport:dport,
                          th_flags:TH_SYN, th_seq:init_seq,th_ack:0,
                          th_x2:0, th_off:5, th_win:2048, th_urp:0);



    reply2 =  send_packet(pcap_active : TRUE,
                        pcap_filter : filter,
                        pcap_timeout : 5,
                        tcp);


    winsize = get_tcp_element(tcp:reply2, element:"th_win");
    flags = get_tcp_element(tcp:reply2, element:"th_flags");
    if ( (flags & TH_ACK) && (flags & TH_SYN) && (winsize == 10) ) {
        set_kb_item(name:"Host/dead", value:TRUE);
        exit(0);
    }

exit(0);



