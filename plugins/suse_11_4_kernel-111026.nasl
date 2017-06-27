#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-5359.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75881);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2011-1577", "CVE-2011-1776", "CVE-2011-1833", "CVE-2011-2183", "CVE-2011-2695", "CVE-2011-2918", "CVE-2011-3191", "CVE-2011-3353", "CVE-2011-3363");
  script_osvdb_id(74624, 74654, 74879, 74910, 75580, 76259);

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2011:1222-1)");
  script_summary(english:"Check for the kernel-5359 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 11.4 kernel was updated to 2.6.37.6 fixing lots of bugs
and security issues.

Following security issues have been fixed: CVE-2011-1833: Added a
kernel option to ensure ecryptfs is mounting only on paths belonging
to the current ui, which would have allowed local attackers to
potentially gain privileges via symlink attacks.

CVE-2011-2695: Multiple off-by-one errors in the ext4 subsystem in the
Linux kernel allowed local users to cause a denial of service (BUG_ON
and system crash) by accessing a sparse file in extent format with a
write operation involving a block number corresponding to the largest
possible 32-bit unsigned integer.

CVE-2011-3363: Always check the path in CIFS mounts to avoid
interesting filesystem path interaction issues and potential crashes.

CVE-2011-2918: In the perf framework software event overflows could
deadlock or delete an uninitialized timer.

CVE-2011-3353: In the fuse filesystem, FUSE_NOTIFY_INVAL_ENTRY did not
check the length of the write so the message processing could overrun
and result in a BUG_ON() in fuse_copy_fill(). This flaw could be used
by local users able to mount FUSE filesystems to crash the system.

CVE-2011-2183: Fixed a race between ksmd and other memory management
code, which could result in a NULL ptr dereference and kernel crash.

CVE-2011-3191: A signedness issue in CIFS could possibly have lead to
to memory corruption, if a malicious server could send crafted replies
to the host.

CVE-2011-1776: The is_gpt_valid function in fs/partitions/efi.c in the
Linux kernel did not check the size of an Extensible Firmware
Interface (EFI) GUID Partition Table (GPT) entry, which allowed
physically proximate attackers to cause a denial of service
(heap-based buffer overflow and OOPS) or obtain sensitive information
from kernel heap memory by connecting a crafted GPT storage device, a
different vulnerability than CVE-2011-1577.

Following non-security bugs were fixed :

  - novfs: Unable to change password in the Novell Client
    for Linux (bnc#713229).

  - novfs: last modification time not reliable (bnc#642896).

  - novfs: unlink directory after unmap (bnc#649625).

  - fs: novfs: Fix exit handlers on local_unlink
    (bnc#649625).

  - novfs: 'Unable to save Login Script' appears when trying
    to save a user login script (bnc#638985).

  - fs: novfs: Limit check for datacopy between user and
    kernel space.

  - novfs: Fix checking of login id (bnc#626119).

  - novfs: Set the sticky bit for the novfs mountpoint
    (bnc#686412).

  - ACPICA: Fix issues/fault with automatic 'serialized'
    method support (bnc#678097).

  - drm/radeon/kms: Fix I2C mask definitions (bnc#712023).

  - ext4: Fix max file size and logical block counting of
    extent format file (bnc#706374).

  - novfs: fix off-by-one allocation error (bnc#669378
    bnc#719710).

  - novfs: fix some kmalloc/kfree issues (bnc#669378
    bnc#719710).

  - novfs: fix some DirCache locking issues (bnc#669378
    bnc#719710).

  - memsw: remove noswapaccount kernel parameter
    (bnc#719450).

  - Provide memory controller swap extension. Keep the
    feature disabled by default. Use swapaccount=1 kernel
    boot parameter for enabling it.

  - Config cleanups: CONFIG_OLPC should be enabled only for
    i386 non PAE

  - TTY: pty, fix pty counting (bnc#711203).

  - USB: OHCI: fix another regression for NVIDIA controllers
    (bnc#682204).

  - xen/blkfront: avoid NULL de-reference in CDROM ioctl
    handling.

  - x86, mtrr: lock stop machine during MTRR rendezvous
    sequence (bnc#672008)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-11/msg00007.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=626119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=638985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=642896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=649625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=669378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=672008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=678097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=682204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=686412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=692784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=697901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=706374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=711203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=711539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=712023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=712366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=713229"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=714001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=716901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=718028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=719450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=719710"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-base-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-base-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-debugsource-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-devel-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-devel-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-base-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-base-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-debugsource-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-devel-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-devel-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-base-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-base-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-debugsource-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-devel-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-devel-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-devel-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-base-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-base-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-debugsource-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-devel-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-devel-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-extra-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-extra-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-base-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-base-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-debugsource-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-devel-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-devel-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-source-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-source-vanilla-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-syms-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-base-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-base-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-debugsource-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-devel-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-devel-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-base-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-base-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-debugsource-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-devel-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-devel-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-base-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-base-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-debugsource-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-devel-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-devel-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-base-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-base-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-debugsource-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-devel-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-devel-debuginfo-2.6.37.6-0.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-kmp-default-1.2_k2.6.37.6_0.9-6.7.20") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-kmp-default-debuginfo-1.2_k2.6.37.6_0.9-6.7.20") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-kmp-desktop-1.2_k2.6.37.6_0.9-6.7.20") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-kmp-desktop-debuginfo-1.2_k2.6.37.6_0.9-6.7.20") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
