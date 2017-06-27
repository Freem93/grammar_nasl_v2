#
# (C) Tenable Network Security, Inc.
#
## script is based on email from wirepair to vuln-dev
#
# From: "wirepair" <wirepair@roguemail.net>
# Subject: lame citrix bug, anyone think of anything interesting?
# To: vuln-dev@securityfocus.com
# Date: Tue, 14 Oct 2003 07:34:25 -0700


include("compat.inc");


if(description)
{
 script_id(11892);
 script_version("$Revision: 1.18 $");
 script_osvdb_id(50623);
 
 script_name(english:"Citrix NFuse Server launch.asp Arbitrary Server/Port Redirect");
 script_summary(english:"Citrix Redirection detection");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server has an information disclosure vulnerability."
 );
 script_set_attribute(attribute:"description", value:
"The remote Citrix NFuse Webserver is vulnerable to a bug wherein any
anonymous user can force the server to redirect to any arbitrary
IP and Port.  Among other things, this flaw can allow an external
attacker to use the Citrix server as a rudimentary port scanner of
either another network or the internal network of which the Citrix
server is a part." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/vuln-dev/2003/Oct/28"
 );
 script_set_attribute(attribute:"solution", value:
"Place your Citrix server behind a reverse proxy or authenticating
firewall." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/10/16");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:nfuse");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ASP");
 exit(0);
}

# start the test

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if ( TARGET_IS_IPV6 ) exit(0);
port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


dirs = make_list("", "/NFuse17", "/NFuse16");

found =  NULL;

foreach dir (dirs)
{
 if(is_cgi_installed3(item:"/Citrix" + dir + "/launch.asp", port:port))
	{
	found = 1;
	break;
	}
}

if(!found)exit(0);



  myaddr = this_host();
  dstaddr = get_host_ip();
  returnport = 5923;
  nfuseport = 3939;
  mystring = string("GET /Citrix/launch.asp?NFuse_CitrixServer=", myaddr, "&NFuse_CitrixServerPort=");
  mystring += string(returnport, "&NFuse_Transport=HTTP&NFuse_Application=N3SSuS");
  mystring += string("&NFUSE_USER=Administrator&NFuse_MIMEExtension=.ica\r\n\r\n");


  filter = string("tcp and src " , dstaddr , " and dst port ", returnport, " and src port ", nfuseport);

  # the stuff in this packet is not important...we just need it in order to get a pcap read
  ippkt2 = forge_ip_packet(
        ip_hl   :5,
        ip_v    :4,
        ip_tos  :0,
        ip_len  :20,
        ip_id   :31338,
        ip_off  :0,
        ip_ttl  :64,
        ip_p    :IPPROTO_TCP,
        ip_src  :myaddr
        );

  tcppacket = forge_tcp_packet(ip:ippkt2,
                               th_sport: rand() % 65535,
                               th_dport: rand() % 65535,
                               th_flags:TH_RST,
                               th_seq: rand(),
                               th_ack: 0,
                               th_x2: 0,
                               th_off: 5,
                               th_win: 8192,
                               th_urp: 0);



  # use send() to blast a packet real quick...then send a phooey packet which shouldn't generate a 
  # reply in order to get a pcap read on the first packet....
  
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  send(socket:soc, data:mystring);
#  close(soc);
  
  rpkt2 = send_packet(tcppacket, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:5);

  if(rpkt2) {
    flags = get_tcp_element(tcp:rpkt2, element:"th_flags");

    if (flags & TH_SYN) {
       security_warning(port);
    }

  }

  close(soc);
  exit(0); 

