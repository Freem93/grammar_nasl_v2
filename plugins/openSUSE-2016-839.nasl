#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-839.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91980);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2015-5745", "CVE-2015-7549", "CVE-2015-8504", "CVE-2015-8558", "CVE-2015-8567", "CVE-2015-8568", "CVE-2015-8613", "CVE-2015-8619", "CVE-2015-8743", "CVE-2015-8744", "CVE-2015-8745", "CVE-2015-8817", "CVE-2015-8818", "CVE-2016-1568", "CVE-2016-1714", "CVE-2016-1922", "CVE-2016-1981", "CVE-2016-2197", "CVE-2016-2198", "CVE-2016-2538", "CVE-2016-2841", "CVE-2016-2857", "CVE-2016-2858", "CVE-2016-3710", "CVE-2016-3712", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037", "CVE-2016-4439", "CVE-2016-4441", "CVE-2016-4952");

  script_name(english:"openSUSE Security Update : qemu (openSUSE-2016-839)");
  script_summary(english:"Check for the openSUSE-2016-839 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"qemu was updated to fix 29 security issues.

These security issues were fixed :

  - CVE-2016-4439: Avoid OOB access in 53C9X emulation
    (bsc#980711)

  - CVE-2016-4441: Avoid OOB access in 53C9X emulation
    (bsc#980723)

  - CVE-2016-4952: Avoid OOB access in Vmware PV SCSI
    emulation (bsc#981266)

  - CVE-2015-8817: Avoid OOB access in PCI dma I/O
    (bsc#969121)

  - CVE-2015-8818: Avoid OOB access in PCI dma I/O
    (bsc#969122)

  - CVE-2016-3710: Fixed VGA emulation based OOB access with
    potential for guest escape (bsc#978158)

  - CVE-2016-3712: Fixed VGa emulation based DOS and OOB
    read access exploit (bsc#978160)

  - CVE-2016-4037: Fixed USB ehci based DOS (bsc#976109)

  - CVE-2016-2538: Fixed potential OOB access in USB net
    device emulation (bsc#967969)

  - CVE-2016-2841: Fixed OOB access / hang in ne2000
    emulation (bsc#969350)

  - CVE-2016-2858: Avoid potential DOS when using QEMU
    pseudo random number generator (bsc#970036)

  - CVE-2016-2857: Fixed OOB access when processing IP
    checksums (bsc#970037)

  - CVE-2016-4001: Fixed OOB access in Stellaris enet
    emulated nic (bsc#975128)

  - CVE-2016-4002: Fixed OOB access in MIPSnet emulated
    controller (bsc#975136)

  - CVE-2016-4020: Fixed possible host data leakage to guest
    from TPR access (bsc#975700)

  - CVE-2016-2197: Prevent AHCI NULL pointer dereference
    when using FIS CLB engine (bsc#964411)

  - CVE-2015-5745: Buffer overflow in virtio-serial
    (bsc#940929).

  - CVE-2015-7549: PCI NULL pointer dereferences
    (bsc#958917).

  - CVE-2015-8504: VNC floating point exception
    (bsc#958491).

  - CVE-2015-8558: Infinite loop in ehci_advance_state
    resulting in DoS (bsc#959005).

  - CVE-2015-8567: A guest repeatedly activating a vmxnet3
    device can leak host memory (bsc#959386).

  - CVE-2015-8568: A guest repeatedly activating a vmxnet3
    device can leak host memory (bsc#959386).

  - CVE-2015-8613: Wrong sized memset in megasas command
    handler (bsc#961358).

  - CVE-2015-8619: Potential DoS for long HMP sendkey
    command argument (bsc#960334).

  - CVE-2015-8743: OOB memory access in ne2000 ioport r/w
    functions (bsc#960725).

  - CVE-2015-8744: Incorrect l2 header validation could have
    lead to a crash via assert(2) call (bsc#960835).

  - CVE-2015-8745: Reading IMR registers could have lead to
    a crash via assert(2) call (bsc#960708).

  - CVE-2016-1568: AHCI use-after-free in aio port commands
    (bsc#961332).

  - CVE-2016-1714: Potential OOB memory access in processing
    firmware configuration (bsc#961691).

  - CVE-2016-1922: NULL pointer dereference when processing
    hmp i/o command (bsc#962320).

  - CVE-2016-1981: Potential DoS (infinite loop) in e1000
    device emulation by malicious privileged user within
    guest (bsc#963782).

  - CVE-2016-2198: Malicious privileged guest user were able
    to cause DoS by writing to read-only EHCI capabilities
    registers (bsc#964413).

This non-security issue was fixed

  - bsc#886378: qemu truncates vhd images in virt-rescue

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=886378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=940929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=976109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981266"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ipxe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-vgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/08");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"qemu-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-arm-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-arm-debuginfo-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-block-curl-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-block-curl-debuginfo-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-debugsource-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-extra-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-extra-debuginfo-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-guest-agent-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-guest-agent-debuginfo-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-ipxe-1.0.0-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-kvm-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-lang-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-linux-user-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-linux-user-debuginfo-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-linux-user-debugsource-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-ppc-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-ppc-debuginfo-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-s390-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-s390-debuginfo-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-seabios-1.8.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-sgabios-8-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-tools-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-tools-debuginfo-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-vgabios-1.8.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-x86-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-x86-debuginfo-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"qemu-block-rbd-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.3.1-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"qemu-testsuite-2.3.1-15.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-linux-user / qemu-linux-user-debuginfo / etc");
}
