#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1477.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95910);
  script_version("$Revision: 3.6 $");
  script_cvs_date("$Date: 2017/02/01 15:30:45 $");

  script_cve_id("CVE-2016-7777", "CVE-2016-7908", "CVE-2016-7909", "CVE-2016-8667", "CVE-2016-8669", "CVE-2016-8910", "CVE-2016-9377", "CVE-2016-9378", "CVE-2016-9379", "CVE-2016-9380", "CVE-2016-9381", "CVE-2016-9382", "CVE-2016-9383", "CVE-2016-9384", "CVE-2016-9385", "CVE-2016-9386", "CVE-2016-9637");
  script_xref(name:"IAVB", value:"2016-B-0149");
  script_xref(name:"IAVB", value:"2016-B-0190");

  script_name(english:"openSUSE Security Update : xen (openSUSE-2016-1477)");
  script_summary(english:"Check for the openSUSE-2016-1477 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"xen was updated to version 4.7.1 to fix 17 security issues.

These security issues were fixed :

  - CVE-2016-9637: ioport array overflow allowing a
    malicious guest administrator can escalate their
    privilege to that of the host (bsc#1011652).

  - CVE-2016-9386: x86 null segments were not always treated
    as unusable allowing an unprivileged guest user program
    to elevate its privilege to that of the guest operating
    system. Exploit of this vulnerability is easy on Intel
    and more complicated on AMD (bsc#1009100).

  - CVE-2016-9382: x86 task switch to VM86 mode was
    mis-handled, allowing a unprivileged guest process to
    escalate its privilege to that of the guest operating
    system on AMD hardware. On Intel hardware a malicious
    unprivileged guest process can crash the guest
    (bsc#1009103).

  - CVE-2016-9385: x86 segment base write emulation lacked
    canonical address checks, allowing a malicious guest
    administrator to crash the host (bsc#1009104).

  - CVE-2016-9384: Guest 32-bit ELF symbol table load
    leaking host data to unprivileged guest users
    (bsc#1009105).

  - CVE-2016-9383: The x86 64-bit bit test instruction
    emulation was broken, allowing a guest to modify
    arbitrary memory leading to arbitray code execution
    (bsc#1009107).

  - CVE-2016-9377: x86 software interrupt injection was
    mis-handled, allowing an unprivileged guest user to
    crash the guest (bsc#1009108).

  - CVE-2016-9378: x86 software interrupt injection was
    mis-handled, allowing an unprivileged guest user to
    crash the guest (bsc#1009108)

  - CVE-2016-9381: Improper processing of shared rings
    allowing guest administrators take over the qemu
    process, elevating their privilege to that of the qemu
    process (bsc#1009109).

  - CVE-2016-9379: Delimiter injection vulnerabilities in
    pygrub allowed guest administrators to obtain the
    contents of sensitive host files or delete the files
    (bsc#1009111).

  - CVE-2016-9380: Delimiter injection vulnerabilities in
    pygrub allowed guest administrators to obtain the
    contents of sensitive host files or delete the files
    (bsc#1009111).

  - CVE-2016-7777: Xen did not properly honor CR0.TS and
    CR0.EM, which allowed local x86 HVM guest OS users to
    read or modify FPU, MMX, or XMM register state
    information belonging to arbitrary tasks on the guest by
    modifying an instruction while the hypervisor is
    preparing to emulate it (bsc#1000106).

  - CVE-2016-8910: The rtl8139_cplus_transmit function in
    hw/net/rtl8139.c allowed local guest OS administrators
    to cause a denial of service (infinite loop and CPU
    consumption) by leveraging failure to limit the ring
    descriptor count (bsc#1007157).

  - CVE-2016-8667: The rc4030_write function in
    hw/dma/rc4030.c in allowed local guest OS administrators
    to cause a denial of service (divide-by-zero error and
    QEMU process crash) via a large interval timer reload
    value (bsc#1005004).

  - CVE-2016-8669: The serial_update_parameters function in
    hw/char/serial.c allowed local guest OS administrators
    to cause a denial of service (divide-by-zero error and
    QEMU process crash) via vectors involving a value of
    divider greater than baud base (bsc#1005005).

  - CVE-2016-7908: The mcf_fec_do_tx function in
    hw/net/mcf_fec.c did not properly limit the buffer
    descriptor count when transmitting packets, which
    allowed local guest OS administrators to cause a denial
    of service (infinite loop and QEMU process crash) via
    vectors involving a buffer descriptor with a length of 0
    and crafted values in bd.flags (bsc#1003030).

  - CVE-2016-7909: The pcnet_rdra_addr function in
    hw/net/pcnet.c allowed local guest OS administrators to
    cause a denial of service (infinite loop and QEMU
    process crash) by setting the (1) receive or (2)
    transmit descriptor ring length to 0 (bsc#1003032).

These non-security issues were fixed :

  - bsc#1004981: Xen RPM didn't contain debug hypervisor for
    EFI systems

  - bsc#1007941: Xen tools limited the number of vcpus to
    256 

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005004"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011652"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/16");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"xen-debugsource-4.7.1_02-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-devel-4.7.1_02-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-libs-4.7.1_02-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-libs-debuginfo-4.7.1_02-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-tools-domU-4.7.1_02-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-tools-domU-debuginfo-4.7.1_02-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-4.7.1_02-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-doc-html-4.7.1_02-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-libs-32bit-4.7.1_02-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.7.1_02-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-tools-4.7.1_02-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-tools-debuginfo-4.7.1_02-3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen-debugsource / xen-devel / xen-libs-32bit / xen-libs / etc");
}
