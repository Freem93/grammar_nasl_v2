#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-4487.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27298);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2007-2525", "CVE-2007-3105", "CVE-2007-3851", "CVE-2007-4571", "CVE-2007-4573");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-4487)");
  script_summary(english:"Check for the kernel-4487 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems :

  - CVE-2007-3105: Stack-based buffer overflow in the random
    number generator (RNG) implementation in the Linux
    kernel before 2.6.22 might allow local root users to
    cause a denial of service or gain privileges by setting
    the default wake-up threshold to a value greater than
    the output pool size, which triggers writing random
    numbers to the stack by the pool transfer function
    involving 'bound check ordering'. Since this value can
    only be changed by a root user, exploitability is low.

  - CVE-2007-2525: A memory leak in the PPPoE driver can be
    abused by local users to cause a denial-of-service
    condition.

  - CVE-2007-3851: On machines with a Intel i965 based
    graphics card local users with access to the direct
    rendering devicenode could overwrite memory on the
    machine and so gain root privileges.

  - CVE-2007-4573: It was possible for local user to become
    root by exploitable a bug in the IA32 system call
    emulation. This affects x86_64 platforms with kernel
    2.4.x and 2.6.x before 2.6.22.7 only.

  - CVE-2007-4571: An information disclosure vulnerability
    in the ALSA driver can be exploited by local users to
    read sensitive data from the kernel memory.

and the following non security bugs :

    - patches.arch/x86-fam10-mtrr: mtrr: fix size_or_mask
      and size_and_mask [#237736]

    - patches.fixes/usb_nokia6233_fix1.patch: usb:
      rndis_host: fix crash while probing a Nokia S60 mobile
      [#244459]

    - patches.fixes/usb_nokia6233_fix2.patch: usbnet: init
      fault (oops) cleanup, whitespace fixes [#244459]

    - patches.fixes/usb_nokia6233_fix2.patch: usb:
      unusual_devs.h entry for Nokia 6233 [#244459]

    - patches.fixes/bt_broadcom_reset.diff: quirky Broadcom
      device [#257303]

    - patches.arch/i386-compat-vdso: i386: allow debuggers
      to access the vsyscall page with compat vDSO [#258433]

  - -
    patches.fixes/anycast6-unbalanced-inet6_dev-refcnt.patch
    : Fix netdevice reference leak when reading from
    /proc/net/anycast6 [#285336]

  - -
    patches.drivers/scsi-throttle-SG_DXFER_TO_FROM_DEV-warni
    ng-b etter: SCSI: throttle SG_DXFER_TO_FROM_DEV warning
    message better [#290117]

  - -
    patches.fixes/nf_conntrack_h323-out-of-bounds-index.diff
    : nf_conntrack_h323: add checking of out-of-range on
    choices' index values [#290611]

    - patches.fixes/ppc-fpu-corruption-fix.diff: ppc: fix
      corruption of fpu [#290622]

  - -
    patches.fixes/ppp-fix-osize-too-small-errors-when-decodi
    ng-m ppe.diff: ppp: Fix osize too small errors when
    decoding mppe [#291102]

    - patches.fixes/hugetlbfs-stack-grows-fix.patch: Don't
      allow the stack to grow into hugetlb reserved regions
      [#294021]

    - patches.fixes/pwc_dos.patch: fix a disconnect method
      waiting for user space to close a file. A malicious
      user can stall khubd indefinitely long [#302063]
      [#302194]

    - patches.suse/kdb.add-unwind-info-to-kdb_call: Add
      unwind info to kdb_call() to fix build of KDB kernel
      on i386 [#305209]

    - Updated config files: enable KDB for kernel-debug on
      i386. [#305209]"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"kernel-bigsmp-2.6.18.8-0.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-default-2.6.18.8-0.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-kdump-2.6.18.8-0.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-source-2.6.18.8-0.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-syms-2.6.18.8-0.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-xen-2.6.18.8-0.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-xenpae-2.6.18.8-0.7") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-bigsmp / kernel-default / kernel-kdump / kernel-source / etc");
}
