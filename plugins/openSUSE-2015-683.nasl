#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-683.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86646);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/01/10 05:42:14 $");

  script_cve_id("CVE-2015-6241", "CVE-2015-6242", "CVE-2015-6243", "CVE-2015-6244", "CVE-2015-6245", "CVE-2015-6246", "CVE-2015-6247", "CVE-2015-6248", "CVE-2015-6249", "CVE-2015-7830");

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-2015-683)");
  script_summary(english:"Check for the openSUSE-2015-683 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"wireshark was updated to version 1.12.8 to fix ten security issues.

These security issues were fixed :

  - CVE-2015-6247: The dissect_openflow_tablemod_v5 function
    in epan/dissectors/packet-openflow_v5.c in the OpenFlow
    dissector in Wireshark 1.12.x before 1.12.7 did not
    validate a certain offset value, which allowed remote
    attackers to cause a denial of service (infinite loop)
    via a crafted packet (bsc#941500).

  - CVE-2015-6246: The dissect_wa_payload function in
    epan/dissectors/packet-waveagent.c in the WaveAgent
    dissector in Wireshark 1.12.x before 1.12.7 mishandles
    large tag values, which allowed remote attackers to
    cause a denial of service (application crash) via a
    crafted packet (bsc#941500).

  - CVE-2015-6245: epan/dissectors/packet-gsm_rlcmac.c in
    the GSM RLC/MAC dissector in Wireshark 1.12.x before
    1.12.7 used incorrect integer data types, which allowed
    remote attackers to cause a denial of service (infinite
    loop) via a crafted packet (bsc#941500).

  - CVE-2015-6244: The dissect_zbee_secure function in
    epan/dissectors/packet-zbee-security.c in the ZigBee
    dissector in Wireshark 1.12.x before 1.12.7 improperly
    relies on length fields contained in packet data, which
    allowed remote attackers to cause a denial of service
    (application crash) via a crafted packet (bsc#941500).

  - CVE-2015-6243: The dissector-table implementation in
    epan/packet.c in Wireshark 1.12.x before 1.12.7
    mishandles table searches for empty strings, which
    allowed remote attackers to cause a denial of service
    (application crash) via a crafted packet, related to the
    (1) dissector_get_string_handle and (2)
    dissector_get_default_string_handle functions
    (bsc#941500).

  - CVE-2015-6242: The wmem_block_split_free_chunk function
    in epan/wmem/wmem_allocator_block.c in the wmem block
    allocator in the memory manager in Wireshark 1.12.x
    before 1.12.7 did not properly consider a certain case
    of multiple realloc operations that restore a memory
    chunk to its original size, which allowed remote
    attackers to cause a denial of service (incorrect free
    operation and application crash) via a crafted packet
    (bsc#941500).

  - CVE-2015-6241: The proto_tree_add_bytes_item function in
    epan/proto.c in the protocol-tree implementation in
    Wireshark 1.12.x before 1.12.7 did not properly
    terminate a data structure after a failure to locate a
    number within a string, which allowed remote attackers
    to cause a denial of service (application crash) via a
    crafted packet (bsc#941500).

  - CVE-2015-7830: pcapng file parser could crash while
    copying an interface filter (bsc#950437).

  - CVE-2015-6249: The dissect_wccp2r1_address_table_info
    function in epan/dissectors/packet-wccp.c in the WCCP
    dissector in Wireshark 1.12.x before 1.12.7 did not
    prevent the conflicting use of a table for both IPv4 and
    IPv6 addresses, which allowed remote attackers to cause
    a denial of service (application crash) via a crafted
    packet (bsc#941500).

  - CVE-2015-6248: The ptvcursor_add function in the
    ptvcursor implementation in epan/proto.c in Wireshark
    1.12.x before 1.12.7 did not check whether the expected
    amount of data is available, which allowed remote
    attackers to cause a denial of service (application
    crash) via a crafted packet (bsc#941500)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=941500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=950437"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.1", reference:"wireshark-1.12.8-43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-debuginfo-1.12.8-43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-debugsource-1.12.8-43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-devel-1.12.8-43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-ui-gtk-1.12.8-43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-ui-gtk-debuginfo-1.12.8-43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-ui-qt-1.12.8-43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-ui-qt-debuginfo-1.12.8-43.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-1.12.8-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-debuginfo-1.12.8-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-debugsource-1.12.8-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-devel-1.12.8-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-gtk-1.12.8-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-gtk-debuginfo-1.12.8-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-qt-1.12.8-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-qt-debuginfo-1.12.8-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-1.12.8-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-debuginfo-1.12.8-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-debugsource-1.12.8-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-devel-1.12.8-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-ui-gtk-1.12.8-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-ui-gtk-debuginfo-1.12.8-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-ui-qt-1.12.8-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-ui-qt-debuginfo-1.12.8-9.1") ) flag++;

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
