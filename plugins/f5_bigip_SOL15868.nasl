#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K15868.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(79601);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/03/28 13:31:42 $");

  script_cve_id("CVE-2013-4074", "CVE-2013-4075", "CVE-2013-4076", "CVE-2013-4077", "CVE-2013-4078", "CVE-2013-4079", "CVE-2013-4080", "CVE-2013-4081", "CVE-2013-4082", "CVE-2013-4083", "CVE-2013-4920", "CVE-2013-4921", "CVE-2013-4922", "CVE-2013-4923", "CVE-2013-4924", "CVE-2013-4925", "CVE-2013-4926", "CVE-2013-4927", "CVE-2013-4928", "CVE-2013-4929", "CVE-2013-4930", "CVE-2013-4931", "CVE-2013-4932", "CVE-2013-4933", "CVE-2013-4934", "CVE-2013-4935", "CVE-2013-4936");
  script_bugtraq_id(60448, 60495, 60498, 60499, 60500, 60501, 60502, 60503, 60504, 60505, 60506, 61471, 62868);
  script_osvdb_id(94244);

  script_name(english:"F5 Networks BIG-IP : Multiple Wireshark vulnerabilities (K15868)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2013-4074 The dissect_capwap_data function in
epan/dissectors/packet-capwap.c in the CAPWAP dissector in Wireshark
1.6.x before 1.6.16 and 1.8.x before 1.8.8 incorrectly uses a -1 data
value to represent an error condition, which allows remote attackers
to cause a denial of service (application crash) via a crafted packet.

CVE-2013-4075 epan/dissectors/packet-gmr1_bcch.c in the GMR-1 BCCH
dissector in Wireshark 1.8.x before 1.8.8 does not properly initialize
memory, which allows remote attackers to cause a denial of service
(application crash) via a crafted packet.

CVE-2013-4076 Buffer overflow in the dissect_iphc_crtp_fh function in
epan/dissectors/packet-ppp.c in the PPP dissector in Wireshark 1.8.x
before 1.8.8 allows remote attackers to cause a denial of service
(application crash) via a crafted packet.

CVE-2013-4077 Array index error in the NBAP dissector in Wireshark
1.8.x before 1.8.8 allows remote attackers to cause a denial of
service (application crash) via a crafted packet, related to nbap.cnf
and packet-nbap.c.

CVE-2013-4078 epan/dissectors/packet-rdp.c in the RDP dissector in
Wireshark 1.8.x before 1.8.8 does not validate return values during
checks for data availability, which allows remote attackers to cause a
denial of service (application crash) via a crafted packet.

CVE-2013-4079 The dissect_schedule_message function in
epan/dissectors/packet-gsm_cbch.c in the GSM CBCH dissector in
Wireshark 1.8.x before 1.8.8 allows remote attackers to cause a denial
of service (infinite loop and application hang) via a crafted packet.

CVE-2013-4080 The dissect_r3_upstreamcommand_queryconfig function in
epan/dissectors/packet-assa_r3.c in the Assa Abloy R3 dissector in
Wireshark 1.8.x before 1.8.8 does not properly handle a zero-length
item, which allows remote attackers to cause a denial of service
(infinite loop, and CPU and memory consumption) via a crafted packet.

CVE-2013-4081 The http_payload_subdissector function in
epan/dissectors/packet-http.c in the HTTP dissector in Wireshark 1.6.x
before 1.6.16 and 1.8.x before 1.8.8 does not properly determine when
to use a recursive approach, which allows remote attackers to cause a
denial of service (stack consumption) via a crafted packet.

CVE-2013-4082 The vwr_read function in wiretap/vwr.c in the Ixia
IxVeriWave file parser in Wireshark 1.8.x before 1.8.8 does not
validate the relationship between a record length and a trailer
length, which allows remote attackers to cause a denial of service
(heap-based buffer overflow and application crash) via a crafted
packet.

CVE-2013-4083 The dissect_pft function in
epan/dissectors/packet-dcp-etsi.c in the DCP ETSI dissector in
Wireshark 1.6.x before 1.6.16, 1.8.x before 1.8.8, and 1.10.0 does not
validate a certain fragment length value, which allows remote
attackers to cause a denial of service (application crash) via a
crafted packet.

CVE-2013-4920 The P1 dissector in Wireshark 1.10.x before 1.10.1 does
not properly initialize a global variable, which allows remote
attackers to cause a denial of service (application crash) via a
crafted packet.

CVE-2013-4921 Off-by-one error in the dissect_radiotap function in
epan/dissectors/packet-ieee80211-radiotap.c in the Radiotap dissector
in Wireshark 1.10.x before 1.10.1 allows remote attackers to cause a
denial of service (application crash) via a crafted packet.

CVE-2013-4922 Double free vulnerability in the
dissect_dcom_ActivationProperties function in
epan/dissectors/packet-dcom-sysact.c in the DCOM ISystemActivator
dissector in Wireshark 1.10.x before 1.10.1 allows remote attackers to
cause a denial of service (application crash) via a crafted packet.

CVE-2013-4923 Memory leak in the dissect_dcom_ActivationProperties
function in epan/dissectors/packet-dcom-sysact.c in the DCOM
ISystemActivator dissector in Wireshark 1.10.x before 1.10.1 allows
remote attackers to cause a denial of service (memory consumption) via
crafted packets.

CVE-2013-4924 epan/dissectors/packet-dcom-sysact.c in the DCOM
ISystemActivator dissector in Wireshark 1.10.x before 1.10.1 does not
properly validate certain index values, which allows remote attackers
to cause a denial of service (assertion failure and application exit)
via a crafted packet.

CVE-2013-4925 Integer signedness error in
epan/dissectors/packet-dcom-sysact.c in the DCOM ISystemActivator
dissector in Wireshark 1.10.x before 1.10.1 allows remote attackers to
cause a denial of service (assertion failure and daemon exit) via a
crafted packet.

CVE-2013-4926 epan/dissectors/packet-dcom-sysact.c in the DCOM
ISystemActivator dissector in Wireshark 1.10.x before 1.10.1 does not
properly determine whether there is remaining packet data to process,
which allows remote attackers to cause a denial of service
(application crash) via a crafted packet.

CVE-2013-4927 Integer signedness error in the get_type_length function
in epan/dissectors/packet-btsdp.c in the Bluetooth SDP dissector in
Wireshark 1.8.x before 1.8.9 and 1.10.x before 1.10.1 allows remote
attackers to cause a denial of service (loop and CPU consumption) via
a crafted packet.

CVE-2013-4928 Integer signedness error in the dissect_headers function
in epan/dissectors/packet-btobex.c in the Bluetooth OBEX dissector in
Wireshark 1.10.x before 1.10.1 allows remote attackers to cause a
denial of service (infinite loop) via a crafted packet.

CVE-2013-4929 The parseFields function in
epan/dissectors/packet-dis-pdus.c in the DIS dissector in Wireshark
1.8.x before 1.8.9 and 1.10.x before 1.10.1 does not terminate
packet-data processing after finding zero remaining bytes, which
allows remote attackers to cause a denial of service (loop) via a
crafted packet.

CVE-2013-4930 The dissect_dvbci_tpdu_hdr function in
epan/dissectors/packet-dvbci.c in the DVB-CI dissector in Wireshark
1.8.x before 1.8.9 and 1.10.x before 1.10.1 does not validate a
certain length value before decrementing it, which allows remote
attackers to cause a denial of service (assertion failure and
application exit) via a crafted packet.

CVE-2013-4931 epan/proto.c in Wireshark 1.8.x before 1.8.9 and 1.10.x
before 1.10.1 allows remote attackers to cause a denial of service
(loop) via a crafted packet that is not properly handled by the GSM RR
dissector.

CVE-2013-4932 Multiple array index errors in
epan/dissectors/packet-gsm_a_common.c in the GSM A Common dissector in
Wireshark 1.8.x before 1.8.9 and 1.10.x before 1.10.1 allow remote
attackers to cause a denial of service (application crash) via a
crafted packet.

CVE-2013-4933 The netmon_open function in wiretap/netmon.c in the
Netmon file parser in Wireshark 1.8.x before 1.8.9 and 1.10.x before
1.10.1 does not properly allocate memory, which allows remote
attackers to cause a denial of service (application crash) via a
crafted packet-trace file.

CVE-2013-4934 The netmon_open function in wiretap/netmon.c in the
Netmon file parser in Wireshark 1.8.x before 1.8.9 and 1.10.x before
1.10.1 does not initialize certain structure members, which allows
remote attackers to cause a denial of service (application crash) via
a crafted packet-trace file.

CVE-2013-4935 The dissect_per_length_determinant function in
epan/dissectors/packet-per.c in the ASN.1 PER dissector in Wireshark
1.8.x before 1.8.9 and 1.10.x before 1.10.1 does not initialize a
length field in certain abnormal situations, which allows remote
attackers to cause a denial of service (application crash) via a
crafted packet.

CVE-2013-4936 The IsDFP_Frame function in
plugins/profinet/packet-pn-rt.c in the PROFINET Real-Time dissector in
Wireshark 1.10.x before 1.10.1 does not validate MAC addresses, which
allows remote attackers to cause a denial of service (NULL pointer
dereference and application crash) via a crafted packet."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/#/article/K15868"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K15868."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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

sol = "K15868";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("11.3.0-11.5.2");
vmatrix["AFM"]["unaffected"] = make_list("11.6.0","11.0.0-11.2.1");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("11.4.0-11.5.2");
vmatrix["AM"]["unaffected"] = make_list("11.6.0");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.3.0-11.5.2");
vmatrix["APM"]["unaffected"] = make_list("11.6.0","11.0.0-11.2.1","10.1.0-10.2.4");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.3.0-11.5.2");
vmatrix["ASM"]["unaffected"] = make_list("11.6.0","11.0.0-11.2.1","10.0.0-10.2.4");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.3.0-11.5.2");
vmatrix["AVR"]["unaffected"] = make_list("11.6.0","11.0.0-11.2.1");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.3.0-11.5.2");
vmatrix["GTM"]["unaffected"] = make_list("11.6.0","11.0.0-11.2.1","10.0.0-10.2.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.3.0-11.5.2");
vmatrix["LC"]["unaffected"] = make_list("11.6.0","11.0.0-11.2.1","10.0.0-10.2.4");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.3.0-11.5.2");
vmatrix["LTM"]["unaffected"] = make_list("11.6.0","11.0.0-11.2.1","10.0.0-10.2.4");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("11.3.0-11.5.2");
vmatrix["PEM"]["unaffected"] = make_list("11.6.0");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.3.0-11.4.1");
vmatrix["PSM"]["unaffected"] = make_list("11.0.0-11.2.1","10.0.0-10.2.4");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("11.3.0");
vmatrix["WAM"]["unaffected"] = make_list("11.0.0-11.2.1","10.0.0-10.2.4");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("11.3.0");
vmatrix["WOM"]["unaffected"] = make_list("11.0.0-11.2.1","10.0.0-10.2.4");


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
