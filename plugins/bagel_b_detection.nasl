# 
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(12063);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2017/04/27 19:46:26 $");

 script_name(english:"Bagle.B Worm Detection");
 script_summary(english:"Checks for Bagle.B");

 script_set_attribute(
   attribute:"synopsis",
   value:"A worm was detected on the remote host."
 );
 script_set_attribute(attribute:"description", value:
"The remote host has the Bagle.B worm installed. This is a variant of
the Bagle worm which spreads via email and has a backdoor that listens
on port 8866." );
 # http://web.archive.org/web/20140414065336/http://antivirus.about.com/cs/allabout/a/bagleb.htm
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?ac5cd26f"
 );
 script_set_attribute(
   attribute:"solution",
   value:"Use an antivirus product to remove the worm."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/17");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");
 script_require_ports(2745, 8866);
 exit(0);
}

#

if ( TARGET_IS_IPV6 ) exit(0);
# so, if we need to add more bagels to the mix....just add them here....
ports[0] = 2745;  desc[0] = "Bagle.Z";
ports[1] = 8866;  desc[1] = "Bagle.B";

for (i=0; ports[i]; i++) {
    if (get_port_state(ports[i]) ) { 
	soc = open_sock_tcp(ports[i]);
	if ( ! soc ) continue;
	close(soc);
        srcaddr = this_host();
        dstaddr = get_host_ip();
        port = ports[i];

        #  gens a RST
        req_rst = raw_string(0x00, 0xA8, 0x00, 0xe6, 0x33, 0x35, 0x37, 0x57, 0x53, 0x00, 0xD0);

        # 00 A8 20 01 1A   generates a FIN
        req_fin = raw_string(0x00, 0xA8, 0x20, 0x01, 0x1A);

        ip = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : 40,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 255,
                        ip_off : 0,
                        ip_src : srcaddr);


        tcpip = forge_tcp_packet(    ip       : ip,
                             th_sport : 44557,
                             th_dport : 139,
                             th_flags : TH_SYN,
                             th_seq   : 0xF1C,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 5,
                             th_win   : 512,
                             th_urp   : 0);

        filter = string("(src or dst ", srcaddr, ") and (src or dst ", dstaddr, ") and  (src or dst port ", port , " ) ");
        soc = open_sock_tcp(port);
        if (soc) {
            send(socket:soc, data:req_fin);
            result = send_packet(tcpip, pcap_active:TRUE, pcap_filter:filter);
            if (result)  {
                flags = get_tcp_element(tcp:result, element:"th_flags");
            }

            if (flags & TH_FIN) {
              finflag = 1;
            }


            # hunt the RST
            ip = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : 40,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 255,
                        ip_off : 0,
                        ip_src : srcaddr);


            tcpip = forge_tcp_packet(    ip       : ip,
                             th_sport : 44556,
                             th_dport : 139,
                             th_flags : TH_SYN,
                             th_seq   : 0xF1C,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 5,
                             th_win   : 512,
                             th_urp   : 0);
            filter = string("(src or dst ", srcaddr, ") and (src or dst ", dstaddr, ") and  (src or dst port ", port , " ) ");
            soc2 = open_sock_tcp(port);
            if (soc2) { 
                send(socket:soc2, data:req_rst);
                result = send_packet(tcpip, pcap_active:TRUE, pcap_filter:filter);

                if (result)  {
                    flags = get_tcp_element(tcp:result, element:"th_flags");
                }

                if (flags & TH_RST) {
                    rstflag = 1;
                }


                if (rstflag && finflag) {
                    strain = desc[i]; 
                    mymsg = string("The remote host has the ", strain, " worm installed.
This is a variant of the Bagle worm which spreads
via email and has a backdoor listener on port ", ports[i] , ".\n");
                    security_hole(port:port, extra:mymsg);
                }
                rstflag = finflag = 0;
		close(soc2);
            } # end if(soc2)
        close (soc);
        } # end if (soc)
    }     # end if (get_port_state(ports[i]) ) {
}         # end for(i=0; etc.




