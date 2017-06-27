#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12213);
  script_version("$Revision: 1.40 $");
  script_cvs_date("$Date: 2016/08/01 18:20:04 $");

  script_cve_id("CVE-2004-0230");
  script_bugtraq_id(10183);
  script_osvdb_id(4030, 13619);
  script_xref(name:"CERT", value:"415294");
  script_xref(name:"EDB-ID", value:"276");
  script_xref(name:"EDB-ID", value:"291");

  script_name(english:"TCP/IP Sequence Prediction Blind Reset Spoofing DoS");
  script_summary(english:"Check for TCP approximations on the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to send spoofed RST packets to the remote system.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by a sequence number approximation
vulnerability that allows an attacker to send spoofed RST packets to
the remote host and close established connections. This may cause
problems for some dedicated services (BGP, a VPN over TCP, etc).");
  script_set_attribute(attribute:"see_also", value:"https://downloads.avaya.com/elmodocs2/security/ASA-2006-217.htm");
  script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/JARL-5ZQR4D");   # Cisco
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IY55949");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IY55950");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IY62006");
  script_set_attribute(attribute:"see_also", value:"http://www.juniper.net/support/security/alerts/niscc-236929.txt");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms05-019");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-064");
  script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/JARL-5YGQ9G");   # Nortel Networks
  script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/JARL-5ZQR7H");   # Redback Networks
  script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/JARL-5YGQAJ");   # Sun
  # https://web.archive.org/web/20060207013513/http://securityresponse.symantec.com/avcenter/security/Content/2005.05.02.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf64c2ca");
  script_set_attribute(attribute:"see_also", value:"http://isc.sans.edu/diary.html?date=2004-04-20");
  script_set_attribute(attribute:"solution", value:"Contact the vendor for a patch or mitigation advice.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/04/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/20");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");
  script_copyright(english:"This script is (C) 2004-2016 Tenable Network Security, Inc.");
  script_dependencies("smb_nativelanman.nasl");
  # We declare that we require ports 139/445 as we don't want to connect to them at the same
  # time as other plugins. Also include ping_host/RTT (which always exists) to make sure that
  # this plugin runs against non-135/445 ports
  script_require_ports(139, 445, "ping_host/RTT");

  exit(0);
}

include('global_settings.inc');

#
# The script code starts here

# if you want to test from CLI, then just supply the two values below
debug=0;

# I think it's worth noting the methodology of this check, as it will likely
# flag on most OSes
# 1) create a valid socket from the Nessus scanner to the host on some open port
# 2) hold the socket from (1) open, and spoof a RST with the sequence number incremented by
#    512 from the valid tuple defining the socket (i.e. srchost, dsthost, srcport, dstport)
# 3) send a character to the socket created in (1)
# 4) check for a RST from the host
# if we get a RST in (4), then that indicates that the system accepted and processed
# our spoofed RST from (2)...and, that is the very nature of this bug.

#if ( report_paranoia < 2 ) exit(0);
if (!defined_func ("get_source_port")) exit(0);
if ( islocalhost() ) exit(0);
if ( TARGET_IS_IPV6 ) exit(0);

# get an open port and name it port
os = get_kb_item ("Host/OS/smb") ;
if ( os && "Windows" >< os)
{
 port = int(get_kb_item("SMB/transport"));
}
else
{
 port = get_host_open_port();
 if ( (!port) && (!debug) ) exit(0);
}

soc = open_sock_tcp (port);
if (!soc) exit(0);
sport = get_source_port (soc);
req = string("G");

#get an ack number from the host 

dstaddr=get_host_ip();
srcaddr=this_host();

filter = string("tcp and src ", dstaddr, " and dst ", srcaddr, " and dst port ", sport, " and src port ", port );

if ( defined_func("send_capture") )
 result = send_capture(socket:soc, data:req, pcap_filter:filter);
else 
{
 send(socket:soc, data:req);
 result = pcap_next(pcap_filter:filter);
}

if (result)  {
  tcp_seq = get_tcp_element(tcp:result, element:"th_ack");
  flags = get_tcp_element(tcp:result, element:"th_flags");
} else {
  if (debug) display("No result packet to pull sequence number from.\n");
  exit(0);
}

# some protocols will take a single character and then close the connection...
# in these instances, we'll just exit the check...remember, only long-lived connections
# are truly at risk 
if  ( (! tcp_seq) || (flags & TH_FIN) || (flags & TH_RST) ) {
    if (debug) display("The remote host has closed the connection prior to our RST packet.\n");
    exit(0); 
}

# now.....SPOOF a RST after incrementing our Sequence num by 512
 
ip2 = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : 20,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 255,
                        ip_off : 0,
                        ip_src : srcaddr);

newsequence = tcp_seq + 512;

tcpip = forge_tcp_packet(    ip       : ip2,
                             th_sport : sport,
                             th_dport : port,
                             th_flags : TH_RST,
                             th_seq   : newsequence,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 5,
                             th_win   : 512,
                             th_urp   : 0);


result = send_packet(tcpip,pcap_active:FALSE);
sleep(1);

result = NULL;
for ( i = 0; i < 3 && ! result; i ++ )
{
 send_packet(tcpip,pcap_active:FALSE);
 if ( defined_func("send_capture") )
  result = send_capture(socket:soc, data:req, pcap_filter:filter, timeout:5);
 else 
  {
  send(socket:soc, data:req);
  result = pcap_next(pcap_filter:filter, timeout:5);
  }
}

if (result) {
    flags = get_tcp_element(tcp:result, element:"th_flags");
    if (flags & TH_RST) {
        if (debug) display("The remote host RSTed our packet, therefore it's vulnerable.\n");
        if( report_paranoia > 1 ) security_warning(0);
        set_kb_item (name:"TCP/seq_window_flaw", value:TRUE);
        exit(0);
    }
} else {
    if ( report_paranoia > 1 )
     {
     # our socket is dead
     if (debug) display("No response on soc, we should have gotten RST ACK or FIN.\n");
     security_warning(0);
     }
    set_kb_item (name:"TCP/seq_window_flaw", value:TRUE);
    exit(0);
 }

# make sure that we don't 'accidentally' FIN our valid socket...this last send call makes sure
# that we hold the socket open till the end of the check....

send(socket:soc, data:req);
close(soc);
