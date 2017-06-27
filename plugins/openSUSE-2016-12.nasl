#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-12.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87833);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:27:28 $");

  script_cve_id("CVE-2015-8711", "CVE-2015-8712", "CVE-2015-8713", "CVE-2015-8714", "CVE-2015-8715", "CVE-2015-8716", "CVE-2015-8717", "CVE-2015-8718", "CVE-2015-8719", "CVE-2015-8720", "CVE-2015-8721", "CVE-2015-8722", "CVE-2015-8723", "CVE-2015-8724", "CVE-2015-8725", "CVE-2015-8726", "CVE-2015-8727", "CVE-2015-8728", "CVE-2015-8729", "CVE-2015-8730", "CVE-2015-8731", "CVE-2015-8732", "CVE-2015-8733");

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-2016-12)");
  script_summary(english:"Check for the openSUSE-2016-12 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Wireshark was updated to 1.12.9 to fix a number of crashes in protocol
dissectors. [boo#960382]

  - CVE-2015-8711: epan/dissectors/packet-nbap.c in the NBAP
    dissector in Wireshark 1.12.x before 1.12.9 and 2.0.x
    before 2.0.1 does not validate conversation data, which
    allows remote attackers to cause a denial of service
    (NULL pointer dereference and application crash) via a
    crafted packet.

  - CVE-2015-8712: The dissect_hsdsch_channel_info function
    in epan/dissectors/packet-umts_fp.c in the UMTS FP
    dissector in Wireshark 1.12.x before 1.12.9 does not
    validate the number of PDUs, which allows remote
    attackers to cause a denial of service (application
    crash) via a crafted packet.

  - CVE-2015-8713: epan/dissectors/packet-umts_fp.c in the
    UMTS FP dissector in Wireshark 1.12.x before 1.12.9 does
    not properly reserve memory for channel ID mappings,
    which allows remote attackers to cause a denial of
    service (out-of-bounds memory access and application
    crash) via a crafted packet.

  - CVE-2015-8714: The dissect_dcom_OBJREF function in
    epan/dissectors/packet-dcom.c in the DCOM dissector in
    Wireshark 1.12.x before 1.12.9 does not initialize a
    certain IPv4 data structure, which allows remote
    attackers to cause a denial of service (application
    crash) via a crafted packet.

  - CVE-2015-8715: epan/dissectors/packet-alljoyn.c in the
    AllJoyn dissector in Wireshark 1.12.x before 1.12.9 does
    not check for empty arguments, which allows remote
    attackers to cause a denial of service (infinite loop)
    via a crafted packet.

  - CVE-2015-8716: The init_t38_info_conv function in
    epan/dissectors/packet-t38.c in the T.38 dissector in
    Wireshark 1.12.x before 1.12.9 does not ensure that a
    conversation exists, which allows remote attackers to
    cause a denial of service (application crash) via a
    crafted packet.

  - CVE-2015-8717: The dissect_sdp function in
    epan/dissectors/packet-sdp.c in the SDP dissector in
    Wireshark 1.12.x before 1.12.9 does not prevent use of a
    negative media count, which allows remote attackers to
    cause a denial of service (application crash) via a
    crafted packet.

  - CVE-2015-8718: Double free vulnerability in
    epan/dissectors/packet-nlm.c in the NLM dissector in
    Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1,
    when the 'Match MSG/RES packets for async NLM' option is
    enabled, allows remote attackers to cause a denial of
    service (application crash) via a crafted packet.

  - CVE-2015-8719: The dissect_dns_answer function in
    epan/dissectors/packet-dns.c in the DNS dissector in
    Wireshark 1.12.x before 1.12.9 mishandles the EDNS0
    Client Subnet option, which allows remote attackers to
    cause a denial of service (application crash) via a
    crafted packet.

  - CVE-2015-8720: The dissect_ber_GeneralizedTime function
    in epan/dissectors/packet-ber.c in the BER dissector in
    Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1
    improperly checks an sscanf return value, which allows
    remote attackers to cause a denial of service
    (application crash) via a crafted packet.

  - CVE-2015-8721: Buffer overflow in the tvb_uncompress
    function in epan/tvbuff_zlib.c in Wireshark 1.12.x
    before 1.12.9 and 2.0.x before 2.0.1 allows remote
    attackers to cause a denial of service (application
    crash) via a crafted packet with zlib compression.

  - CVE-2015-8722: epan/dissectors/packet-sctp.c in the SCTP
    dissector in Wireshark 1.12.x before 1.12.9 and 2.0.x
    before 2.0.1 does not validate the frame pointer, which
    allows remote attackers to cause a denial of service
    (NULL pointer dereference and application crash) via a
    crafted packet.

  - CVE-2015-8723: The AirPDcapPacketProcess function in
    epan/crypt/airpdcap.c in the 802.11 dissector in
    Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1
    does not validate the relationship between the total
    length and the capture length, which allows remote
    attackers to cause a denial of service (stack-based
    buffer overflow and application crash) via a crafted

  - CVE-2015-8724: The AirPDcapDecryptWPABroadcastKey
    function in epan/crypt/airpdcap.c in the 802.11
    dissector in Wireshark 1.12.x before 1.12.9 and 2.0.x
    before 2.0.1 does not verify the WPA broadcast key
    length, which allows remote attackers to cause a denial
    of service (out-of-bounds read and application crash)
    via a crafted packet.

  - CVE-2015-8725: The
    dissect_diameter_base_framed_ipv6_prefix function in
    epan/dissectors/packet-diameter.c in the DIAMETER
    dissector in Wireshark 1.12.x before 1.12.9 and 2.0.x
    before 2.0.1 does not validate the IPv6 prefix length,
    which allows remote attackers to cause a denial of
    service (stack-based buffer overflow and application
    crash) via a crafted packet.

  - CVE-2015-8726: wiretap/vwr.c in the VeriWave file parser
    in Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1
    does not validate certain signature and Modulation and
    Coding Scheme (MCS) data, which allows remote attackers
    to cause a denial of service (out-of-bounds read and
    application crash) via a crafted file.

  - CVE-2015-8727: The dissect_rsvp_common function in
    epan/dissectors/packet-rsvp.c in the RSVP dissector in
    Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1
    does not properly maintain request-key data, which
    allows remote attackers to cause a denial of service
    (use-after-free and application crash) via a crafted
    packet.

  - CVE-2015-8728: The Mobile Identity parser in (1)
    epan/dissectors/packet-ansi_a.c in the ANSI A dissector
    and (2) epan/dissectors/packet-gsm_a_common.c in the GSM
    A dissector in Wireshark 1.12.x before 1.12.9 and 2.0.x
    before 2.0.1 improperly uses the
    tvb_bcd_dig_to_wmem_packet_str function, which allows
    remote attackers to cause a denial of service (buffer
    overflow and application crash) via a crafted packet.

  - CVE-2015-8729: The ascend_seek function in
    wiretap/ascendtext.c in the Ascend file parser in
    Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1
    does not ensure the presence of a '\0' character at the
    end of a date string, which allows remote attackers to
    cause a denial of service (out-of-bounds read and
    application crash) via a crafted file.

  - CVE-2015-8730: epan/dissectors/packet-nbap.c in the NBAP
    dissector in Wireshark 1.12.x before 1.12.9 and 2.0.x
    before 2.0.1 does not validate the number of items,
    which allows remote attackers to cause a denial of
    service (invalid read operation and application crash)
    via a crafted packet.

  - CVE-2015-8731: The dissct_rsl_ipaccess_msg function in
    epan/dissectors/packet-rsl.c in the RSL dissector in
    Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1
    does not reject unknown TLV types, which allows remote
    attackers to cause a denial of service (out-of-bounds
    read and application crash) via a crafted packet.

  - CVE-2015-8732: The dissect_zcl_pwr_prof_pwrprofstatersp
    function in epan/dissectors/packet-zbee-zcl-general.c in
    the ZigBee ZCL dissector in Wireshark 1.12.x before
    1.12.9 and 2.0.x before 2.0.1 does not validate the
    Total Profile Number field, which allows remote
    attackers to cause a denial of service (out-of-bounds
    read and application crash) via a crafted packet.

  - CVE-2015-8733: The ngsniffer_process_record function in
    wiretap/ngsniffer.c in the Sniffer file parser in
    Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1
    does not validate the relationships between record
    lengths and record header lengths, which allows remote
    attackers to cause a denial of service (out-of-bounds
    read and application crash) via a crafted file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960382"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE13\.1|SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"wireshark-1.12.9-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-debuginfo-1.12.9-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-debugsource-1.12.9-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-devel-1.12.9-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-ui-gtk-1.12.9-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-ui-gtk-debuginfo-1.12.9-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-ui-qt-1.12.9-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-ui-qt-debuginfo-1.12.9-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-1.12.9-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-debuginfo-1.12.9-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-debugsource-1.12.9-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-devel-1.12.9-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-gtk-1.12.9-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-gtk-debuginfo-1.12.9-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-qt-1.12.9-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-qt-debuginfo-1.12.9-29.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-1.12.9-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-debuginfo-1.12.9-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-debugsource-1.12.9-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-devel-1.12.9-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-ui-gtk-1.12.9-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-ui-gtk-debuginfo-1.12.9-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-ui-qt-1.12.9-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-ui-qt-debuginfo-1.12.9-14.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-debuginfo / wireshark-debugsource / etc");
}
