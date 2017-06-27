#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K01837042.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(91838);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2017/03/15 20:36:15 $");

  script_cve_id("CVE-2015-8711", "CVE-2015-8714", "CVE-2015-8716", "CVE-2015-8717", "CVE-2015-8718", "CVE-2015-8720", "CVE-2015-8721", "CVE-2015-8723", "CVE-2015-8725", "CVE-2015-8729", "CVE-2015-8730", "CVE-2015-8733", "CVE-2016-2523", "CVE-2016-4006", "CVE-2016-4078", "CVE-2016-4079", "CVE-2016-4080", "CVE-2016-4081", "CVE-2016-4085");
  script_osvdb_id(131892, 131897, 131899, 131900, 132143, 132406, 132407, 132418, 132421, 132422, 132424, 132425, 135093, 136225, 136558, 137564, 137565, 137566, 137573);

  script_name(english:"F5 Networks BIG-IP : Multiple Wireshark (tshark) vulnerabilities (K01837042)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2015-8711 epan/dissectors/packet-nbap.c in the NBAP dissector in
Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1 does not
validate conversation data, which allows remote attackers to cause a
denial of service (NULL pointer dereference and application crash) via
a crafted packet.

CVE-2015-8714 The dissect_dcom_OBJREF function in
epan/dissectors/packet-dcom.c in the DCOM dissector in Wireshark
1.12.x before 1.12.9 does not initialize a certain IPv4 data
structure, which allows remote attackers to cause a denial of service
(application crash) via a crafted packet.

CVE-2015-8716 The init_t38_info_conv function in
epan/dissectors/packet-t38.c in the T.38 dissector in Wireshark 1.12.x
before 1.12.9 does not ensure that a conversation exists, which allows
remote attackers to cause a denial of service (application crash) via
a crafted packet.

CVE-2015-8717 The dissect_sdp function in epan/dissectors/packet-sdp.c
in the SDP dissector in Wireshark 1.12.x before 1.12.9 does not
prevent use of a negative media count, which allows remote attackers
to cause a denial of service (application crash) via a crafted packet.

CVE-2015-8718 Double free vulnerability in
epan/dissectors/packet-nlm.c in the NLM dissector in Wireshark 1.12.x
before 1.12.9 and 2.0.x before 2.0.1, when the 'Match MSG/RES packets
for async NLM' option is enabled, allows remote attackers to cause a
denial of service (application crash) via a crafted packet.

CVE-2015-8720 The dissect_ber_GeneralizedTime function in
epan/dissectors/packet-ber.c in the BER dissector in Wireshark 1.12.x
before 1.12.9 and 2.0.x before 2.0.1 improperly checks an sscanf
return value, which allows remote attackers to cause a denial of
service (application crash) via a crafted packet.

CVE-2015-8721 Buffer overflow in the tvb_uncompress function in
epan/tvbuff_zlib.c in Wireshark 1.12.x before 1.12.9 and 2.0.x before
2.0.1 allows remote attackers to cause a denial of service
(application crash) via a crafted packet with zlib compression.

CVE-2015-8723 The AirPDcapPacketProcess function in
epan/crypt/airpdcap.c in the 802.11 dissector in Wireshark 1.12.x
before 1.12.9 and 2.0.x before 2.0.1 does not validate the
relationship between the total length and the capture length, which
allows remote attackers to cause a denial of service (stack-based
buffer overflow and application crash) via a crafted packet.

CVE-2015-8725 The dissect_diameter_base_framed_ipv6_prefix function in
epan/dissectors/packet-diameter.c in the DIAMETER dissector in
Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1 does not
validate the IPv6 prefix length, which allows remote attackers to
cause a denial of service (stack-based buffer overflow and application
crash) via a crafted packet.

CVE-2015-8729 The ascend_seek function in wiretap/ascendtext.c in the
Ascend file parser in Wireshark 1.12.x before 1.12.9 and 2.0.x before
2.0.1 does not ensure the presence of a '\0' character at the end of a
date string, which allows remote attackers to cause a denial of
service (out-of-bounds read and application crash) via a crafted file.

CVE-2015-8730 epan/dissectors/packet-nbap.c in the NBAP dissector in
Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1 does not
validate the number of items, which allows remote attackers to cause a
denial of service (invalid read operation and application crash) via a
crafted packet.

CVE-2015-8733 The ngsniffer_process_record function in
wiretap/ngsniffer.c in the Sniffer file parser in Wireshark 1.12.x
before 1.12.9 and 2.0.x before 2.0.1 does not validate the
relationships between record lengths and record header lengths, which
allows remote attackers to cause a denial of service (out-of-bounds
read and application crash) via a crafted file.

CVE-2016-2523 The dnp3_al_process_object function in
epan/dissectors/packet-dnp.c in the DNP3 dissector in Wireshark 1.12.x
before 1.12.10 and 2.0.x before 2.0.2 allows remote attackers to cause
a denial of service (infinite loop) via a crafted packet.

CVE-2016-4006 epan/proto.c in Wireshark 1.12.x before 1.12.11 and
2.0.x before 2.0.3 does not limit the protocol-tree depth, which
allows remote attackers to cause a denial of service (stack memory
consumption and application crash) via a crafted packet.

CVE-2016-4078 The IEEE 802.11 dissector in Wireshark 1.12.x before
1.12.11 and 2.0.x before 2.0.3 does not properly restrict element
lists, which allows remote attackers to cause a denial of service
(deep recursion and application crash) via a crafted packet, related
to epan/dissectors/packet-capwap.c and
epan/dissectors/packet-ieee80211.c.

CVE-2016-4079 epan/dissectors/packet-pktc.c in the PKTC dissector in
Wireshark 1.12.x before 1.12.11 and 2.0.x before 2.0.3 does not verify
BER identifiers, which allows remote attackers to cause a denial of
service (out-of-bounds write and application crash) via a crafted
packet.

CVE-2016-4080 epan/dissectors/packet-pktc.c in the PKTC dissector in
Wireshark 1.12.x before 1.12.11 and 2.0.x before 2.0.3 misparses
timestamp fields, which allows remote attackers to cause a denial of
service (out-of-bounds read and application crash) via a crafted
packet.

CVE-2016-4081 epan/dissectors/packet-iax2.c in the IAX2 dissector in
Wireshark 1.12.x before 1.12.11 and 2.0.x before 2.0.3 uses an
incorrect integer data type, which allows remote attackers to cause a
denial of service (infinite loop) via a crafted packet.

CVE-2016-4085 Stack-based buffer overflow in
epan/dissectors/packet-ncp2222.inc in the NCP dissector in Wireshark
1.12.x before 1.12.11 allows remote attackers to cause a denial of
service (application crash) or possibly have unspecified other impact
via a long string in a packet."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/#/article/K01837042"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K01837042."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"F5 Networks Local Security Checks");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version", "Settings/ParanoidReport");

  exit(0);
}


include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(get_kb_item("Host/BIG-IP/hotfix")) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

sol = "K01837042";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("12.0.0-12.1.1","11.4.0-11.6.1");
vmatrix["APM"]["unaffected"] = make_list("11.2.1","10.2.1-10.2.4");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("12.0.0-12.1.1","11.4.0-11.6.1");
vmatrix["ASM"]["unaffected"] = make_list("11.2.1","10.2.1-10.2.4");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("12.0.0-12.1.1","11.4.0-11.6.1");
vmatrix["AVR"]["unaffected"] = make_list("11.2.1");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.4.0-11.6.1");
vmatrix["GTM"]["unaffected"] = make_list("11.2.1","10.2.1-10.2.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("12.0.0-12.1.1","11.4.0-11.6.1");
vmatrix["LC"]["unaffected"] = make_list("11.2.1","10.2.1-10.2.4");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("12.0.0-12.1.1","11.4.0-11.6.1");
vmatrix["LTM"]["unaffected"] = make_list("11.2.1","10.2.1-10.2.4");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.4.0-11.4.1");
vmatrix["PSM"]["unaffected"] = make_list("10.2.1-10.2.4");


if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (report_verbosity > 0) security_hole(port:0, extra:bigip_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = bigip_get_tested_modules();
  audit_extra = "For BIG-IP module(s) " + tested + ",";
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, "running any of the affected modules");
}
