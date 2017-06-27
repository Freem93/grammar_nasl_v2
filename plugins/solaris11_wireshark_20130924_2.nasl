#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80808);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2013-4920", "CVE-2013-4921", "CVE-2013-4922", "CVE-2013-4923", "CVE-2013-4924", "CVE-2013-4925", "CVE-2013-4926", "CVE-2013-4927", "CVE-2013-4928", "CVE-2013-4929", "CVE-2013-4930", "CVE-2013-4931", "CVE-2013-4932", "CVE-2013-4933", "CVE-2013-4934", "CVE-2013-4935", "CVE-2013-4936");

  script_name(english:"Oracle Solaris Third-Party Patch Update : wireshark (multiple_vulnerabilities_in_wireshark6)");
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

  - The P1 dissector in Wireshark 1.10.x before 1.10.1 does
    not properly initialize a global variable, which allows
    remote attackers to cause a denial of service
    (application crash) via a crafted packet.
    (CVE-2013-4920)

  - Off-by-one error in the dissect_radiotap function in
    epan/dissectors/ packet-ieee80211-radiotap.c in the
    Radiotap dissector in Wireshark 1.10.x before 1.10.1
    allows remote attackers to cause a denial of service
    (application crash) via a crafted packet.
    (CVE-2013-4921)

  - Double free vulnerability in the
    dissect_dcom_ActivationProperties function in
    epan/dissectors/packet-dcom-sysact.c in the DCOM
    ISystemActivator dissector in Wireshark 1.10.x before
    1.10.1 allows remote attackers to cause a denial of
    service (application crash) via a crafted packet.
    (CVE-2013-4922)

  - Memory leak in the dissect_dcom_ActivationProperties
    function in epan/ dissectors/packet-dcom-sysact.c in the
    DCOM ISystemActivator dissector in Wireshark 1.10.x
    before 1.10.1 allows remote attackers to cause a denial
    of service (memory consumption) via crafted packets.
    (CVE-2013-4923)

  - epan/dissectors/packet-dcom-sysact.c in the DCOM
    ISystemActivator dissector in Wireshark 1.10.x before
    1.10.1 does not properly validate certain index values,
    which allows remote attackers to cause a denial of
    service (assertion failure and application exit) via a
    crafted packet. (CVE-2013-4924)

  - Integer signedness error in
    epan/dissectors/packet-dcom-sysact.c in the DCOM
    ISystemActivator dissector in Wireshark 1.10.x before
    1.10.1 allows remote attackers to cause a denial of
    service (assertion failure and daemon exit) via a
    crafted packet. (CVE-2013-4925)

  - epan/dissectors/packet-dcom-sysact.c in the DCOM
    ISystemActivator dissector in Wireshark 1.10.x before
    1.10.1 does not properly determine whether there is
    remaining packet data to process, which allows remote
    attackers to cause a denial of service (application
    crash) via a crafted packet. (CVE-2013-4926)

  - Integer signedness error in the get_type_length function
    in epan/dissectors/ packet-btsdp.c in the Bluetooth SDP
    dissector in Wireshark 1.8.x before 1.8.9 and 1.10.x
    before 1.10.1 allows remote attackers to cause a denial
    of service (loop and CPU consumption) via a crafted
    packet. (CVE-2013-4927)

  - Integer signedness error in the dissect_headers function
    in epan/dissectors/ packet-btobex.c in the Bluetooth
    OBEX dissector in Wireshark 1.10.x before 1.10.1 allows
    remote attackers to cause a denial of service (infinite
    loop) via a crafted packet. (CVE-2013-4928)

  - The parseFields function in
    epan/dissectors/packet-dis-pdus.c in the DIS dissector
    in Wireshark 1.8.x before 1.8.9 and 1.10.x before 1.10.1
    does not terminate packet-data processing after finding
    zero remaining bytes, which allows remote attackers to
    cause a denial of service (loop) via a crafted packet.
    (CVE-2013-4929)

  - The dissect_dvbci_tpdu_hdr function in
    epan/dissectors/packet-dvbci.c in the DVB-CI dissector
    in Wireshark 1.8.x before 1.8.9 and 1.10.x before 1.10.1
    does not validate a certain length value before
    decrementing it, which allows remote attackers to cause
    a denial of service (assertion failure and application
    exit) via a crafted packet. (CVE-2013-4930)

  - epan/proto.c in Wireshark 1.8.x before 1.8.9 and 1.10.x
    before 1.10.1 allows remote attackers to cause a denial
    of service (loop) via a crafted packet that is not
    properly handled by the GSM RR dissector.
    (CVE-2013-4931)

  - Multiple array index errors in
    epan/dissectors/packet-gsm_a_common.c in the GSM A
    Common dissector in Wireshark 1.8.x before 1.8.9 and
    1.10.x before 1.10.1 allow remote attackers to cause a
    denial of service (application crash) via a crafted
    packet. (CVE-2013-4932)

  - The netmon_open function in wiretap/netmon.c in the
    Netmon file parser in Wireshark 1.8.x before 1.8.9 and
    1.10.x before 1.10.1 does not properly allocate memory,
    which allows remote attackers to cause a denial of
    service (application crash) via a crafted packet-trace
    file. (CVE-2013-4933)

  - The netmon_open function in wiretap/netmon.c in the
    Netmon file parser in Wireshark 1.8.x before 1.8.9 and
    1.10.x before 1.10.1 does not initialize certain
    structure members, which allows remote attackers to
    cause a denial of service (application crash) via a
    crafted packet-trace file. (CVE-2013-4934)

  - The dissect_per_length_determinant function in
    epan/dissectors/packet-per.c in the ASN.1 PER dissector
    in Wireshark 1.8.x before 1.8.9 and 1.10.x before 1.10.1
    does not initialize a length field in certain abnormal
    situations, which allows remote attackers to cause a
    denial of service (application crash) via a crafted
    packet. (CVE-2013-4935)

  - The IsDFP_Frame function in
    plugins/profinet/packet-pn-rt.c in the PROFINET
    Real-Time dissector in Wireshark 1.10.x before 1.10.1
    does not validate MAC addresses, which allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and application crash) via a crafted packet.
    (CVE-2013-4936)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_wireshark6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5a8556d"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.11.4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:wireshark");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
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

if (solaris_check_release(release:"0.5.11-0.175.1.11.0.4.0", sru:"SRU 11.1.11.4.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : wireshark\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "wireshark");
