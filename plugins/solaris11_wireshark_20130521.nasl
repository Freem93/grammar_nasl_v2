#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80806);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2012-6052", "CVE-2012-6053", "CVE-2012-6054", "CVE-2012-6055", "CVE-2012-6056", "CVE-2012-6057", "CVE-2012-6058", "CVE-2012-6059", "CVE-2012-6060", "CVE-2012-6061", "CVE-2012-6062");

  script_name(english:"Oracle Solaris Third-Party Patch Update : wireshark (multiple_vulnerabilities_fixed_in_wireshark)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - Wireshark 1.8.x before 1.8.4 allows remote attackers to
    obtain sensitive hostname information by reading pcap-ng
    files. (CVE-2012-6052)

  - epan/dissectors/packet-usb.c in the USB dissector in
    Wireshark 1.6.x before 1.6.12 and 1.8.x before 1.8.4
    relies on a length field to calculate an offset value,
    which allows remote attackers to cause a denial of
    service (infinite loop) via a zero value for this field.
    (CVE-2012-6053)

  - The dissect_sflow_245_address_type function in
    epan/dissectors/packet-sflow.c in the sFlow dissector in
    Wireshark 1.8.x before 1.8.4 does not properly handle
    length calculations for an invalid IP address type,
    which allows remote attackers to cause a denial of
    service (infinite loop) via a packet that is neither
    IPv4 nor IPv6. (CVE-2012-6054)

  - epan/dissectors/packet-3g-a11.c in the 3GPP2 A11
    dissector in Wireshark 1.8.x before 1.8.4 allows remote
    attackers to cause a denial of service (infinite loop)
    via a zero value in a sub-type length field.
    (CVE-2012-6055)

  - Integer overflow in the dissect_sack_chunk function in
    epan/dissectors/ packet-sctp.c in the SCTP dissector in
    Wireshark 1.8.x before 1.8.4 allows remote attackers to
    cause a denial of service (infinite loop) via a crafted
    Duplicate TSN count. (CVE-2012-6056)

  - The dissect_eigrp_metric_comm function in
    epan/dissectors/packet-eigrp.c in the EIGRP dissector in
    Wireshark 1.8.x before 1.8.4 uses the wrong data type
    for a certain offset value, which allows remote
    attackers to cause a denial of service (integer overflow
    and infinite loop) via a malformed packet.
    (CVE-2012-6057)

  - Integer overflow in the dissect_icmpv6 function in
    epan/dissectors/ packet-icmpv6.c in the ICMPv6 dissector
    in Wireshark 1.6.x before 1.6.12 and 1.8.x before 1.8.4
    allows remote attackers to cause a denial of service
    (infinite loop) via a crafted Number of Sources value.
    (CVE-2012-6058)

  - The dissect_isakmp function in
    epan/dissectors/packet-isakmp.c in the ISAKMP dissector
    in Wireshark 1.6.x before 1.6.12 and 1.8.x before 1.8.4
    uses an incorrect data structure to determine IKEv2
    decryption parameters, which allows remote attackers to
    cause a denial of service (application crash) via a
    malformed packet. (CVE-2012-6059)

  - Integer overflow in the dissect_iscsi_pdu function in
    epan/dissectors/ packet-iscsi.c in the iSCSI dissector
    in Wireshark 1.6.x before 1.6.12 and 1.8.x before 1.8.4
    allows remote attackers to cause a denial of service
    (infinite loop) via a malformed packet. (CVE-2012-6060)

  - The dissect_wtp_common function in
    epan/dissectors/packet-wtp.c in the WTP dissector in
    Wireshark 1.6.x before 1.6.12 and 1.8.x before 1.8.4
    uses an incorrect data type for a certain length field,
    which allows remote attackers to cause a denial of
    service (integer overflow and infinite loop) via a
    crafted value in a packet. (CVE-2012-6061)

  - The dissect_rtcp_app function in
    epan/dissectors/packet-rtcp.c in the RTCP dissector in
    Wireshark 1.6.x before 1.6.12 and 1.8.x before 1.8.4
    allows remote attackers to cause a denial of service
    (infinite loop) via a crafted packet. (CVE-2012-6062)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_fixed_in_wireshark
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6244415"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.7.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:wireshark");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^wireshark$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.7.0.5.0", sru:"SRU 11.1.7.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : wireshark\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "wireshark");
