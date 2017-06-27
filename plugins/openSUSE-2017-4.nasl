#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-4.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96252);
  script_version("$Revision: 3.7 $");
  script_cvs_date("$Date: 2017/02/01 15:30:45 $");

  script_cve_id("CVE-2016-10013", "CVE-2016-10024", "CVE-2016-7777", "CVE-2016-7908", "CVE-2016-7909", "CVE-2016-7995", "CVE-2016-8576", "CVE-2016-8667", "CVE-2016-8669", "CVE-2016-8909", "CVE-2016-8910", "CVE-2016-9101", "CVE-2016-9377", "CVE-2016-9378", "CVE-2016-9379", "CVE-2016-9380", "CVE-2016-9381", "CVE-2016-9382", "CVE-2016-9383", "CVE-2016-9385", "CVE-2016-9386", "CVE-2016-9637", "CVE-2016-9776", "CVE-2016-9932");
  script_xref(name:"IAVB", value:"2016-B-0149");
  script_xref(name:"IAVB", value:"2017-B-0008");

  script_name(english:"openSUSE Security Update : xen (openSUSE-2017-4)");
  script_summary(english:"Check for the openSUSE-2017-4 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This updates xen to version 4.5.5 to fix the following issues :

  - An unprivileged user in a guest could gain guest could
    escalate privilege to that of the guest kernel, if it
    had could invoke the instruction emulator. Only 64-bit
    x86 HVM guest were affected. Linux guest have not been
    vulnerable. (boo#1016340, CVE-2016-10013)

  - An unprivileged user in a 64 bit x86 guest could gain
    information from the host, crash the host or gain
    privilege of the host (boo#1009107, CVE-2016-9383)

  - An unprivileged guest process could (unintentionally or
    maliciously) obtain or ocorrupt sensitive information of
    other programs in the same guest. Only x86 HVM guests
    have been affected. The attacker needs to be able to
    trigger the Xen instruction emulator. (boo#1000106,
    CVE-2016-7777)

  - A guest on x86 systems could read small parts of
    hypervisor stack data (boo#1012651, CVE-2016-9932)

  - A malicious guest kernel could hang or crash the host
    system (boo#1014298, CVE-2016-10024)

  - The epro100 emulated network device caused a memory leak
    in the host when unplugged in the guest. A privileged
    user in the guest could use this to cause a DoS on the
    host or potentially crash the guest process on the host
    (boo#1013668, CVE-2016-9101)

  - The ColdFire Fast Ethernet Controller was vulnerable to
    an infinite loop that could be trigged by a privileged
    user in the guest, leading to DoS (boo#1013657,
    CVE-2016-9776)

  - A malicious guest administrator could escalate their
    privilege to that of the host. Only affects x86 HVM
    guests using qemu older version 1.6.0 or using the
    qemu-xen-traditional. (boo#1011652, CVE-2016-9637)

  - An unprivileged guest user could escalate privilege to
    that of the guest administrator on x86 HVM guests,
    especially on Intel CPUs (boo#1009100, CVE-2016-9386)

  - An unprivileged guest user could escalate privilege to
    that of the guest administrator (on AMD CPUs) or crash
    the system (on Intel CPUs) on 32-bit x86 HVM guests.
    Only guest operating systems that allowed a new task to
    start in VM86 mode were affected. (boo#1009103,
    CVE-2016-9382)

  - A malicious guest administrator could crash the host on
    x86 PV guests only (boo#1009104, CVE-2016-9385)

  - An unprivileged guest user was able to crash the guest.
    (boo#1009108, CVE-2016-9377, CVE-2016-9378)

  - A malicious guest administrator could get privilege of
    the host emulator process on x86 HVM guests.
    (boo#1009109, CVE-2016-9381)

  - A vulnerability in pygrub allowed a malicious guest
    administrator to obtain the contents of sensitive host
    files, or even delete those files (boo#1009111,
    CVE-2016-9379, CVE-2016-9380)

  - A privileged guest user could cause an infinite loop in
    the RTL8139 ethernet emulation to consume CPU cycles on
    the host, causing a DoS situation (boo#1007157,
    CVE-2016-8910)

  - A privileged guest user could cause an infinite loop in
    the intel-hda sound emulation to consume CPU cycles on
    the host, causing a DoS situation (boo#1007160,
    CVE-2016-8909)

  - A privileged guest user could cause a crash of the
    emulator process on the host by exploiting a divide by
    zero vulnerability of the JAZZ RC4030 chipset emulation
    (boo#1005004 CVE-2016-8667)

  - A privileged guest user could cause a crash of the
    emulator process on the host by exploiting a divide by
    zero issue of the 16550A UART emulation (boo#1005005,
    CVE-2016-8669)

  - A privileged guest user could cause a memory leak in the
    USB EHCI emulation, causing a DoS situation on the host
    (boo#1003870, CVE-2016-7995)

  - A privileged guest user could cause an infinite loop in
    the USB xHCI emulation, causing a DoS situation on the
    host (boo#1004016, CVE-2016-8576)

  - A privileged guest user could cause an infinite loop in
    the ColdFire Fash Ethernet Controller emulation, causing
    a DoS situation on the host (boo#1003030, CVE-2016-7908)

  - A privileged guest user could cause an infinite loop in
    the AMD PC-Net II emulation, causing a DoS situation on
    the host (boo#1003032, CVE-2016-7909)

  - Cause a reload of clvm in the block-dmmd script to avoid
    a blocking lvchange call (boo#1002496)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002496"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004016"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007160"
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
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016340"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/03");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"xen-debugsource-4.5.5_06-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xen-devel-4.5.5_06-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xen-libs-4.5.5_06-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xen-libs-debuginfo-4.5.5_06-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xen-tools-domU-4.5.5_06-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xen-tools-domU-debuginfo-4.5.5_06-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-4.5.5_06-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-doc-html-4.5.5_06-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-kmp-default-4.5.5_06_k4.1.36_41-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.5.5_06_k4.1.36_41-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-libs-32bit-4.5.5_06-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.5.5_06-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-tools-4.5.5_06-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-tools-debuginfo-4.5.5_06-18.1") ) flag++;

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
