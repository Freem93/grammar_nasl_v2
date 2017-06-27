#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80816);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2014-6421", "CVE-2014-6422", "CVE-2014-6423", "CVE-2014-6424", "CVE-2014-6425", "CVE-2014-6426", "CVE-2014-6427", "CVE-2014-6428", "CVE-2014-6429", "CVE-2014-6430", "CVE-2014-6431", "CVE-2014-6432");

  script_name(english:"Oracle Solaris Third-Party Patch Update : wireshark (multiple_vulnerabilities_in_wireshark11)");
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

  - Use-after-free vulnerability in the SDP dissector in
    Wireshark 1.10.x before 1.10.10 allows remote attackers
    to cause a denial of service (application crash) via a
    crafted packet that leverages split memory ownership
    between the SDP and RTP dissectors. (CVE-2014-6421)

  - The SDP dissector in Wireshark 1.10.x before 1.10.10
    creates duplicate hashtables for a media channel, which
    allows remote attackers to cause a denial of service
    (application crash) via a crafted packet to the RTP
    dissector. (CVE-2014-6422)

  - The tvb_raw_text_add function in
    epan/dissectors/packet-megaco.c in the MEGACO dissector
    in Wireshark 1.10.x before 1.10.10 and 1.12.x before
    1.12.1 allows remote attackers to cause a denial of
    service (infinite loop) via an empty line.
    (CVE-2014-6423)

  - The dissect_v9_v10_pdu_data function in
    epan/dissectors/packet-netflow.c in the Netflow
    dissector in Wireshark 1.10.x before 1.10.10 and 1.12.x
    before 1.12.1 refers to incorrect offset and start
    variables, which allows remote attackers to cause a
    denial of service (uninitialized memory read and
    application crash) via a crafted packet. (CVE-2014-6424)

  - The (1) get_quoted_string and (2) get_unquoted_string
    functions in epan/ dissectors/packet-cups.c in the CUPS
    dissector in Wireshark 1.12.x before 1.12.1 allow remote
    attackers to cause a denial of service (buffer over-read
    and application crash) via a CUPS packet that lacks a
    trailing '\0' character. (CVE-2014-6425)

  - The dissect_hip_tlv function in
    epan/dissectors/packet-hip.c in the HIP dissector in
    Wireshark 1.12.x before 1.12.1 does not properly handle
    a NULL tree, which allows remote attackers to cause a
    denial of service (infinite loop) via a crafted packet.
    (CVE-2014-6426)

  - Off-by-one error in the is_rtsp_request_or_reply
    function in epan/dissectors/ packet-rtsp.c in the RTSP
    dissector in Wireshark 1.10.x before 1.10.10 and 1.12.x
    before 1.12.1 allows remote attackers to cause a denial
    of service (application crash) via a crafted packet that
    triggers parsing of a token located one position beyond
    the current position. (CVE-2014-6427)

  - The dissect_spdu function in
    epan/dissectors/packet-ses.c in the SES dissector in
    Wireshark 1.10.x before 1.10.10 and 1.12.x before 1.12.1
    does not initialize a certain ID value, which allows
    remote attackers to cause a denial of service
    (application crash) via a crafted packet.
    (CVE-2014-6428)

  - The SnifferDecompress function in wiretap/ngsniffer.c in
    the DOS Sniffer file parser in Wireshark 1.10.x before
    1.10.10 and 1.12.x before 1.12.1 does not properly
    handle empty input data, which allows remote attackers
    to cause a denial of service (application crash) via a
    crafted file. (CVE-2014-6429)

  - The SnifferDecompress function in wiretap/ngsniffer.c in
    the DOS Sniffer file parser in Wireshark 1.10.x before
    1.10.10 and 1.12.x before 1.12.1 does not validate
    bitmask data, which allows remote attackers to cause a
    denial of service (application crash) via a crafted
    file. (CVE-2014-6430)

  - Buffer overflow in the SnifferDecompress function in
    wiretap/ngsniffer.c in the DOS Sniffer file parser in
    Wireshark 1.10.x before 1.10.10 and 1.12.x before 1.12.1
    allows remote attackers to cause a denial of service
    (application crash) via a crafted file that triggers
    writes of uncompressed bytes beyond the end of the
    output buffer. (CVE-2014-6431)

  - The SnifferDecompress function in wiretap/ngsniffer.c in
    the DOS Sniffer file parser in Wireshark 1.10.x before
    1.10.10 and 1.12.x before 1.12.1 does not prevent data
    overwrites during copy operations, which allows remote
    attackers to cause a denial of service (application
    crash) via a crafted file. (CVE-2014-6432)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_wireshark11
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad9f40ee"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.2.4.6.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:wireshark");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/20");
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

if (solaris_check_release(release:"0.5.11-0.175.2.4.0.6.0", sru:"SRU 11.2.4.6.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : wireshark\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "wireshark");
