#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(56283);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2014/05/26 00:51:57 $");

 script_cve_id("CVE-2011-3188");
 script_bugtraq_id(49289);
 script_osvdb_id(75716);

 script_name(english:"Linux Kernel TCP Sequence Number Generation Security Weakness");
 script_summary(english:"Checks for predictable TCP Sequence Numbers generated by the Linux kernel");

 script_set_attribute(attribute:"synopsis", value:
"It may be possible to predict TCP/IP Initial Sequence Numbers for the
remote host.");
 script_set_attribute(attribute:"description", value:
"The Linux kernel is prone to a security weakness related to TCP
sequence number generation. Attackers can exploit this issue to inject
arbitrary packets into TCP sessions using a brute-force attack.

An attacker may use this vulnerability to create a denial of service
condition or a man-in-the-middle attack.

Note that this plugin may fire as a result of a network device (such
as a load balancer, VPN, IPS, transparent proxy, etc.) that is
vulnerable and that re-writes TCP sequence numbers, rather than the
host itself being vulnerable.");
 script_set_attribute(attribute:"see_also", value:"http://lwn.net/Articles/455135/");
 # https://github.com/mirrors/linux-2.6/commit/6e5714eaf77d79ae1c8b47e3e040ff5411b717ec
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9881d9af");
 script_set_attribute(attribute:"solution", value:"Contact the OS vendor for a Linux kernel update / patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/23");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
 script_family(english:"General");

 script_require_keys("Settings/ParanoidReport");

 exit(0);
}


include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( TARGET_IS_IPV6 ) exit(1, "This check is not implemented for IPv6 hosts.");

MAX_RETRIES = 5;
PROBES      = 100;

# Send a probe to a specific port (and from a specific port), and return the
# sequence number.
function probe(dport, sport)
{
  local_var flags, ip, tcp, filter, i, rep;

  ip = forge_ip_packet(ip_hl   : 5,
                       ip_v    : 4,
                       ip_tos  : 0,
                       ip_len  : 20,
                       ip_id   : 31338,
                       ip_off  : 0,
                       ip_ttl  : 64,
                       ip_p    : IPPROTO_TCP,
                       ip_src  : this_host()
                      );

  tcp = forge_tcp_packet(ip :       ip,
                         th_sport : sport,
                         th_dport : dport,
                         th_flags : TH_SYN,
                         th_seq   : 0,
                         th_ack   : 0,
                         th_x2    : 0,
                         th_off   : 5,
                         th_win   : 8192,
                         th_urp   : 0
                        );

  # Note: these ports look backwards because we're capturing the response
  filter = "tcp and src host " + get_host_ip() + " and src port " + dport + " and dst port " + sport;
  for (i = 0; i < MAX_RETRIES; i++ )
  {
    rep = send_packet(tcp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
    if(rep) break;
  }

  if (!rep) exit(1, "Didn't receive a response to the probes.");

  flags = get_tcp_element(tcp:rep, element:"th_flags");
  if(flags != (TH_SYN|TH_ACK)) exit(1, "The host didn't respond to our probe with with SYN/ACK.");

  return get_tcp_element(tcp:rep, element:"th_seq");
}

# Calculate the average in the given list
function average(list)
{
  local_var total, i, x;

  total = bn_dec2raw(0);
  for(i = 0; i < max_index(list); i++)
  {
    # To get rid of signs, we half it then double it
    x = bn_dec2raw((list[i] >> 1) & 0x7FFFFFFF);
    x = bn_add(x, x);
    total = bn_add(total, x);
  }

  return bn_raw2dec(bn_div(total, bn_dec2raw(max_index(list))));
}

# Calculate the variance in the list of values
function variance(list)
{
  local_var average, total, i;

  average = bn_dec2raw(average(list:list));
  total = bn_dec2raw(0);

  for(i = 0; i < max_index(list); i++)
    total = bn_add(total, bn_sqr(bn_dec2raw(list[i]) - average));
  total = bn_div(total, max_index(list));

  return bn_raw2dec(total);
}

# Get an open port
port = get_host_open_port();
if (isnull(port) || !port) exit(1, "Couldn't find an open port to check.");

# Get a sample of sequence numbers and the delta values
seqs = make_list();
deltas = make_list();
for(i = 0; i < PROBES; i++)
{
  seqs[i] = probe(dport:port, sport:(rand() % (65535 - 1024)) + 1024);
  if(i > 0)
  {
    deltas[i - 1] = seqs[i] - seqs[i - 1];
  }
}

v = variance(list:deltas);
if(strlen(v) < 11) exit(1, "The server had an unexpectedly low variance in sequence numbers, likely due to other sequence-number issues.");
else if(strlen(v) < 15) security_warning(0);
else exit(0, "The host does not appear to be affected.");
