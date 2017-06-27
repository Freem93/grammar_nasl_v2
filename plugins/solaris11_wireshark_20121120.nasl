#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80804);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2012-4285", "CVE-2012-4286", "CVE-2012-4287", "CVE-2012-4288", "CVE-2012-4289", "CVE-2012-4290", "CVE-2012-4291", "CVE-2012-4292", "CVE-2012-4293", "CVE-2012-4294", "CVE-2012-4295", "CVE-2012-4296", "CVE-2012-4297", "CVE-2012-4298");

  script_name(english:"Oracle Solaris Third-Party Patch Update : wireshark (multiple_vulnerabilities_in_wireshark3)");
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

  - The dissect_pft function in
    epan/dissectors/packet-dcp-etsi.c in the DCP ETSI
    dissector in Wireshark 1.4.x before 1.4.15, 1.6.x before
    1.6.10, and 1.8.x before 1.8.2 allows remote attackers
    to cause a denial of service (divide-by-zero error and
    application crash) via a zero-length message.
    (CVE-2012-4285)

  - The pcapng_read_packet_block function in
    wiretap/pcapng.c in the pcap-ng file parser in Wireshark
    1.8.x before 1.8.2 allows user-assisted remote attackers
    to cause a denial of service (divide-by-zero error and
    application crash) via a crafted pcap-ng file.
    (CVE-2012-4286)

  - epan/dissectors/packet-mongo.c in the MongoDB dissector
    in Wireshark 1.8.x before 1.8.2 allows remote attackers
    to cause a denial of service (loop and CPU consumption)
    via a small value for a BSON document length.
    (CVE-2012-4287)

  - Integer overflow in the dissect_xtp_ecntl function in
    epan/dissectors/ packet-xtp.c in the XTP dissector in
    Wireshark 1.4.x before 1.4.15, 1.6.x before 1.6.10, and
    1.8.x before 1.8.2 allows remote attackers to cause a
    denial of service (loop or application crash) via a
    large value for a span length. (CVE-2012-4288)

  - epan/dissectors/packet-afp.c in the AFP dissector in
    Wireshark 1.4.x before 1.4.15, 1.6.x before 1.6.10, and
    1.8.x before 1.8.2 allows remote attackers to cause a
    denial of service (loop and CPU consumption) via a large
    number of ACL entries. (CVE-2012-4289)

  - The CTDB dissector in Wireshark 1.4.x before 1.4.15,
    1.6.x before 1.6.10, and 1.8.x before 1.8.2 allows
    remote attackers to cause a denial of service (loop and
    CPU consumption) via a malformed packet. (CVE-2012-4290)

  - The CIP dissector in Wireshark 1.4.x before 1.4.15,
    1.6.x before 1.6.10, and 1.8.x before 1.8.2 allows
    remote attackers to cause a denial of service (memory
    consumption) via a malformed packet. (CVE-2012-4291)

  - The dissect_stun_message function in
    epan/dissectors/packet-stun.c in the STUN dissector in
    Wireshark 1.4.x before 1.4.15, 1.6.x before 1.6.10, and
    1.8.x before 1.8.2 does not properly interact with
    key-destruction behavior in a certain tree library,
    which allows remote attackers to cause a denial of
    service (application crash) via a malformed packet.
    (CVE-2012-4292)

  - plugins/ethercat/packet-ecatmb.c in the EtherCAT Mailbox
    dissector in Wireshark 1.4.x before 1.4.15, 1.6.x before
    1.6.10, and 1.8.x before 1.8.2 does not properly handle
    certain integer fields, which allows remote attackers to
    cause a denial of service (application exit) via a
    malformed packet. (CVE-2012-4293)

  - Buffer overflow in the channelised_fill_sdh_g707_format
    function in epan/ dissectors/packet-erf.c in the ERF
    dissector in Wireshark 1.8.x before 1.8.2 allows remote
    attackers to execute arbitrary code via a large speed
    (aka rate) value. (CVE-2012-4294)

  - Array index error in the
    channelised_fill_sdh_g707_format function in epan/
    dissectors/packet-erf.c in the ERF dissector in
    Wireshark 1.8.x before 1.8.2 might allow remote
    attackers to cause a denial of service (application
    crash) via a crafted speed (aka rate) value.
    (CVE-2012-4295)

  - Buffer overflow in epan/dissectors/packet-rtps2.c in the
    RTPS2 dissector in Wireshark 1.4.x before 1.4.15, 1.6.x
    before 1.6.10, and 1.8.x before 1.8.2 allows remote
    attackers to cause a denial of service (CPU consumption)
    via a malformed packet. (CVE-2012-4296)

  - Buffer overflow in the dissect_gsm_rlcmac_downlink
    function in epan/dissectors/ packet-gsm_rlcmac.c in the
    GSM RLC MAC dissector in Wireshark 1.6.x before 1.6.10
    and 1.8.x before 1.8.2 allows remote attackers to
    execute arbitrary code via a malformed packet.
    (CVE-2012-4297)

  - Integer signedness error in the
    vwr_read_rec_data_ethernet function in wiretap/ vwr.c in
    the Ixia IxVeriWave file parser in Wireshark 1.8.x
    before 1.8.2 allows user-assisted remote attackers to
    execute arbitrary code via a crafted packet-trace file
    that triggers a buffer overflow. (CVE-2012-4298)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_wireshark3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f688cd9b"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 13.4.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:wireshark");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/20");
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

if (solaris_check_release(release:"0.5.11-0.175.0.13.0.4.0", sru:"SRU 13.4") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : wireshark\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "wireshark");
