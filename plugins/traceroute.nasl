#TRUSTED 9213eed914919a10cb88ba7a1ba6796e1a12a7b70eddbba2b724817b6efe56184df6e2beefa77774e08caded222db6e32f37e78316752ea7466ceca34d044f048d546222bf98c42f141cd16013d0cef6e4217387bef79126d911cfbc43bad5dc437172e3f1f4ce5a349ffb5c5d8422e73e78c70c8c6b188770657b43360e1e0caab266829c0a873afb9fe37edc25495e2d9f394ae7582cc7c043cfef823fe6769069d0b095c90160d046a74270486fa7d1ddfc3858190c717b608114684e71349d45aa8eb92eecfb9aa72593415547c519ae510d7c0216c969801bb0501c71f8cd692d3bc0a8546caf209b6bace1e88a4adab4eae93f24a3ea73c90ea165182e8c09506f04610b795e4046d7132013c51b7d4a2733e98dcbac2baca964c9a9d48fa7d3ce363201e493da7f70a8785a666c88bc2b7c01a1ab8b61c98c41b19a9cca67b2cafbd4fa85c7ce03edeed1d0b71616dd30597343d71711bc42cc31df571cc44429a2cfd3bc9e3166ae70466b1abe9512096ef3b25ea1eacbb58d9d70dba8f7dff621be99931cc805435751ae6194eb690ee5f85384fd104e638744c779c577596c4c4e3774cc62cb4bbbe9ae320468498c90d1bb354384326fc9b73f638813d87ac89b0657666d24118130dac799bafd3af95d4f0249518e3c505df2e679ccee35a69d202255051b59dc27e335e732bec9aafd072d34e05f5731397fc6
#
# (C) Tenable Network Security, Inc.
#

if ( isnull(NESSUS_VERSION) ) exit(0);


include("compat.inc");

if (description)
{
 script_id(10287);
 script_version("1.62");
 script_set_attribute(attribute:"plugin_modification_date", value: "2013/04/11");

 script_name(english:"Traceroute Information");
 script_summary(english:"traceroute");

 script_set_attribute(attribute:"synopsis", value:"It was possible to obtain traceroute information.");
 script_set_attribute(attribute:"description", value:"Makes a traceroute to the remote host.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/11/27");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2013 Tenable Network Security, Inc.");
 script_family(english:"General");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");

if (TARGET_IS_IPV6) exit(0, "This check is not implemented for IPv6 hosts.");
if (islocalhost()) exit(1, "localhost can not be tested.");


dport = get_host_open_port();
if(!dport)dport = 80;

ip_id = rand() % 65535;

my_sport = rand() % 64000 + 1024;

finished = 0;
ttl = 1;
src = this_host();
dst = get_host_ip();
error = 0;

str_ip = string(dst);
z = strstr(str_ip, ".");

#
# pcap filtter
#


ip_fields = split(dst, sep:'.', keep:0);
ip_high = (int(ip_fields[0]) << 8) | int(ip_fields[1]);
ip_low = (int(ip_fields[2]) << 8) | int(ip_fields[3]);

#
report = string("For your information, here is the traceroute from ", src, " to ", dst, " : \n", this_host(), "\n");
filter = string("dst host ", src, " and ((icmp and ((icmp[0]=3) or (icmp[0]=11)) and ((icmp[8] & 0xF0) = 0x40) and icmp[12:2]=", ip_id," and icmp[24:2]=",ip_high, " and icmp[26:2]=",ip_low, ")" +
		" or (src host ", get_host_ip(), " and tcp and tcp[0:2]=", dport, " and tcp[2:2]=", my_sport, " and (tcp[13]=4 or tcp[13]=18)))");

debug_print(level: 2, 'Filter=', filter, '\n');
d = get_host_ip();
prev = string("");

#
# the traceroute itself
#


function make_pkt(ttl, proto)
{
  local_var ip, p, src;

  #proto = proto % 5;
  #display("make_pkt(", ttl, ", ", proto, ")\n");
  src = this_host();


   # Prefer TCP
   if( proto == 0 || proto > 2)
   {
    ip = forge_ip_packet(ip_v : 4, ip_hl:5, ip_tos:0, ip_id:ip_id,
			ip_len:20, ip_off:0, ip_p:IPPROTO_TCP,
			ip_src:src, ip_ttl:ttl);

    p = forge_tcp_packet(ip:ip, th_sport:my_sport, th_dport: dport,
			th_flags: TH_SYN, th_seq: ttl,
			th_ack: 0, th_x2    : 0,th_off   : 5,
			th_win   : 2048, th_urp   : 0);

   }


  # then UDP
  if (proto == 1)
  {
    ip = forge_ip_packet(ip_v : 4, ip_hl:5, ip_tos:0, ip_id:ip_id,
			ip_len:28, ip_off:0, ip_p:IPPROTO_UDP,
			ip_src:src, ip_ttl:ttl);
    p = forge_udp_packet(ip:ip, uh_sport:my_sport, uh_dport:32768, uh_ulen:8);
    return (p);
  }
  # then ICMP
  if (proto == 2)
  {
    ip = forge_ip_packet(ip_v : 4, ip_hl:5, ip_tos:0, ip_id:ip_id,
			ip_len:20, ip_off:0, ip_p:IPPROTO_ICMP,
			ip_src:src, ip_ttl:ttl);
    p = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0,
			icmp_seq: ttl, icmp_id:ttl);
    return (p);
  }

    return (p);
}

proto=0;	# Prefer TCP
gateway_n = 0;

count = make_list();

if ( defined_func("platform") && platform() == "WINDOWS" && NASL_LEVEL >= 5000 ) mutex_lock(SCRIPT_NAME);

while(!finished)
{
 for (i=0; i < 3; i=i+1)
 {
  err=1;
  p = make_pkt(ttl: ttl, proto: proto);
  rep = send_packet(p, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:5);
  then = unixtime();

  if(rep)
  {
   psrc = get_ip_element(ip:rep, element:"ip_src");
   #display("+", psrc, "\n");
   if (++ count[psrc] >= 3) exit(0, "Encountered a loop.");	# We are running in circles
   gateway[gateway_n ++] = psrc;
   d = psrc - d;
   if(!d)finished = 1;
   d = get_host_ip();
   error = 0; err=0;
   i=666;
  }
  else
  {
   proto++;
   if(proto >= 3)err = 1;
   else err = 0;
   proto%=3;
  }
 }
 if(err)
 {
  #display("...\");
  if (!error) gateway[gateway_n++] = '?';
  error = error+1;
 }
 ttl = ttl+1;

 #
 # If we get more than 3 errors one after another, we stop
 #
 if(error > 3)finished = 1;

 #
 # Should not get here
 #
 if(ttl > 50)finished = 1;
}

if ( defined_func("platform") && platform() == "WINDOWS" && NASL_LEVEL >= 5000 ) mutex_unlock(SCRIPT_NAME);

max = 0;
for (i = 1; i < max_index(gateway); i ++)
 if (gateway[i] != gateway[i-1])
  max = i;
 else
  debug_print('Duplicate router #', i, '(', gateway[i], ') in trace to ', get_host_ip(), '\n');

for (i = 0; i <= max; i ++)
{
 report = strcat(report, gateway[i], '\n');
 if (defined_func("report_xml_tag"))
   report_xml_tag(tag:'traceroute-hop-' + i, value:gateway[i]);
 set_kb_item(name:'traceroute-hop/' + i, value:gateway[i]);
}
#
# show if at least one route was obtained.
#
# MA 2002-08-15: I split the expression "ttl=ttl-(1+error)" because of
# what looked like a NASL bug
y = 1 + error;
ttl = ttl - y;
if (ttl > 0)
security_note(port:0, protocol:"udp", extra:report);
