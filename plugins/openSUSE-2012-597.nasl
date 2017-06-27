#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-597.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74750);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-2625", "CVE-2012-3432", "CVE-2012-3433", "CVE-2012-3494", "CVE-2012-3495", "CVE-2012-3496", "CVE-2012-3498", "CVE-2012-3515");

  script_name(english:"openSUSE Security Update : Xen (openSUSE-SU-2012:1172-1)");
  script_summary(english:"Check for the openSUSE-2012-597 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security Update for Xen

Following bug and security fixes were applied :

  - bnc#776995 - attaching scsi control luns with pvscsi

  - xend/pvscsi: fix passing of SCSI control LUNs
    xen-bug776995-pvscsi-no-devname.patch

  - xend/pvscsi: fix usage of persistant device names for
    SCSI devices xen-bug776995-pvscsi-persistent-names.patch

  - xend/pvscsi: update sysfs parser for Linux 3.0
    xen-bug776995-pvscsi-sysfs-parser.patch

  - bnc#777090 - CVE-2012-3494: xen: hypercall set_debugreg
    vulnerability (XSA-12) CVE-2012-3494-xsa12.patch

  - bnc#777088 - CVE-2012-3495: xen: hypercall
    physdev_get_free_pirq vulnerability (XSA-13)
    CVE-2012-3495-xsa13.patch

  - bnc#777091 - CVE-2012-3496: xen: XENMEM_populate_physmap
    DoS vulnerability (XSA-14) CVE-2012-3496-xsa14.patch

  - bnc#777086 - CVE-2012-3498: xen: PHYSDEVOP_map_pirq
    index vulnerability (XSA-16) CVE-2012-3498-xsa16.patch

  - bnc#777084 - CVE-2012-3515: xen: Qemu VT100 emulation
    vulnerability (XSA-17) CVE-2012-3515-xsa17.patch

  - Upstream patches from Jan
    25734-x86-MCG_CTL-default.patch
    25735-x86-cpuid-masking-XeonE5.patch
    25744-hypercall-return-long.patch

  - Update to Xen 4.1.3 c/s 23336 

  - Upstream or pending upstream patches from Jan
    25587-fix-off-by-one-parsing-error.patch
    25616-x86-MCi_CTL-default.patch
    25617-vtd-qinval-addr.patch 25688-x86-nr_irqs_gsi.patch

  - bnc#773393 - VUL-0: CVE-2012-3433: xen: HVM guest
    destroy p2m teardown host DoS vulnerability
    CVE-2012-3433-xsa11.patch

  - bnc#773401 - VUL-1: CVE-2012-3432: xen: HVM guest user
    mode MMIO emulation DoS
    25682-x86-inconsistent-io-state.patch

  - bnc#762484 - VUL-1: CVE-2012-2625: xen: pv bootloader
    doesn't check the size of the bzip2 or lzma compressed
    kernel, leading to denial of service
    25589-pygrub-size-limits.patch

  - bnc#767273 - unsupported /var/lock/subsys is still used
    by xendomains init.xendomains

  - bnc#766283 - opensuse 12.2 pv guests can not start after
    installation due to lack of grub2 support in the host
    23686-pygrub-solaris.patch 23697-pygrub-grub2.patch
    23944-pygrub-debug.patch 23998-pygrub-GPT.patch
    23999-pygrub-grub2.patch 24000-pygrub-grub2.patch
    24001-pygrub-grub2.patch 24002-pygrub-grub2.patch
    24064-pygrub-HybridISO.patch
    24401-pygrub-scrolling.patch 24402-pygrub-edit-fix.patch
    24460-pygrub-extlinux.patch 24706-pygrub-extlinux.patch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-09/msg00059.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=766283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=767273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777091"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected Xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/06");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"xen-debugsource-4.1.3_01-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-devel-4.1.3_01-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-kmp-default-4.1.3_01_k3.1.10_1.16-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-kmp-default-debuginfo-4.1.3_01_k3.1.10_1.16-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-kmp-desktop-4.1.3_01_k3.1.10_1.16-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-kmp-desktop-debuginfo-4.1.3_01_k3.1.10_1.16-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-kmp-pae-4.1.3_01_k3.1.10_1.16-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-kmp-pae-debuginfo-4.1.3_01_k3.1.10_1.16-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-libs-4.1.3_01-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-libs-debuginfo-4.1.3_01-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-tools-domU-4.1.3_01-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-tools-domU-debuginfo-4.1.3_01-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-4.1.3_01-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-doc-html-4.1.3_01-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-doc-pdf-4.1.3_01-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-libs-32bit-4.1.3_01-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.1.3_01-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-tools-4.1.3_01-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-tools-debuginfo-4.1.3_01-1.13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen-debugsource / xen-devel / xen-kmp-default / etc");
}
