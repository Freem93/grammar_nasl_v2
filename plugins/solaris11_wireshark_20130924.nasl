#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80807);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2013-2486", "CVE-2013-2487", "CVE-2013-3555", "CVE-2013-3556", "CVE-2013-3557", "CVE-2013-3558", "CVE-2013-3559", "CVE-2013-3560", "CVE-2013-3561", "CVE-2013-3562", "CVE-2013-4083");

  script_name(english:"Oracle Solaris Third-Party Patch Update : wireshark (multiple_vulnerabilities_in_wireshark5)");
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

  - The dissect_diagnosticrequest function in
    epan/dissectors/packet-reload.c in the REsource LOcation
    And Discovery (aka RELOAD) dissector in Wireshark 1.8.x
    before 1.8.6 uses an incorrect integer data type, which
    allows remote attackers to cause a denial of service
    (infinite loop) via crafted integer values in a packet.
    (CVE-2013-2486)

  - epan/dissectors/packet-reload.c in the REsource LOcation
    And Discovery (aka RELOAD) dissector in Wireshark 1.8.x
    before 1.8.6 uses incorrect integer data types, which
    allows remote attackers to cause a denial of service
    (infinite loop) via crafted integer values in a packet,
    related to the (1) dissect_icecandidates, (2)
    dissect_kinddata, (3) dissect_nodeid_list, (4)
    dissect_storeans, (5) dissect_storereq, (6)
    dissect_storeddataspecifier, (7) dissect_fetchreq, (8)
    dissect_findans, (9) dissect_diagnosticinfo, (10)
    dissect_diagnosticresponse, (11)
    dissect_reload_messagecontents, and (12)
    dissect_reload_message functions, a different
    vulnerability than CVE-2013-2486. (CVE-2013-2487)

  - epan/dissectors/packet-gtpv2.c in the GTPv2 dissector in
    Wireshark 1.8.x before 1.8.7 calls incorrect functions
    in certain contexts related to ciphers, which allows
    remote attackers to cause a denial of service
    (application crash) via a malformed packet.
    (CVE-2013-3555)

  - The fragment_add_seq_common function in
    epan/reassemble.c in the ASN.1 BER dissector in
    Wireshark before r48943 has an incorrect pointer
    dereference during a comparison, which allows remote
    attackers to cause a denial of service (application
    crash) via a malformed packet. (CVE-2013-3556)

  - The dissect_ber_choice function in
    epan/dissectors/packet-ber.c in the ASN.1 BER dissector
    in Wireshark 1.6.x before 1.6.15 and 1.8.x before 1.8.7
    does not properly initialize a certain variable, which
    allows remote attackers to cause a denial of service
    (application crash) via a malformed packet.
    (CVE-2013-3557)

  - The dissect_ccp_bsdcomp_opt function in
    epan/dissectors/packet-ppp.c in the PPP CCP dissector in
    Wireshark 1.8.x before 1.8.7 does not terminate a
    bit-field list, which allows remote attackers to cause a
    denial of service (application crash) via a malformed
    packet. (CVE-2013-3558)

  - epan/dissectors/packet-dcp-etsi.c in the DCP ETSI
    dissector in Wireshark 1.8.x before 1.8.7 uses incorrect
    integer data types, which allows remote attackers to
    cause a denial of service (integer overflow, and heap
    memory corruption or NULL pointer dereference, and
    application crash) via a malformed packet.
    (CVE-2013-3559)

  - The dissect_dsmcc_un_download function in
    epan/dissectors/packet-mpeg-dsmcc.c in the MPEG DSM-CC
    dissector in Wireshark 1.8.x before 1.8.7 uses an
    incorrect format string, which allows remote attackers
    to cause a denial of service (application crash) via a
    malformed packet. (CVE-2013-3560)

  - Multiple integer overflows in Wireshark 1.8.x before
    1.8.7 allow remote attackers to cause a denial of
    service (loop or application crash) via a malformed
    packet, related to a crash of the Websocket dissector,
    an infinite loop in the MySQL dissector, and a large
    loop in the ETCH dissector. (CVE-2013-3561)

  - Multiple integer signedness errors in the tvb_unmasked
    function in epan/ dissectors/packet-websocket.c in the
    Websocket dissector in Wireshark 1.8.x before 1.8.7
    allow remote attackers to cause a denial of service
    (application crash) via a malformed packet.
    (CVE-2013-3562)

  - The dissect_pft function in
    epan/dissectors/packet-dcp-etsi.c in the DCP ETSI
    dissector in Wireshark 1.6.x before 1.6.16, 1.8.x before
    1.8.8, and 1.10.0 does not validate a certain fragment
    length value, which allows remote attackers to cause a
    denial of service (application crash) via a crafted
    packet. (CVE-2013-4083)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_wireshark5
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2145bb15"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.10.5.0.");
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

if (solaris_check_release(release:"0.5.11-0.175.1.10.0.5.0", sru:"SRU 11.1.10.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : wireshark\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "wireshark");
