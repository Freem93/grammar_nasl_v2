#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-812.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74821);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2007-0998", "CVE-2012-2625", "CVE-2012-2934", "CVE-2012-3494", "CVE-2012-3495", "CVE-2012-3496", "CVE-2012-3497", "CVE-2012-3498", "CVE-2012-3515", "CVE-2012-4411", "CVE-2012-4535", "CVE-2012-4536", "CVE-2012-4537", "CVE-2012-4538", "CVE-2012-4539", "CVE-2012-4544");

  script_name(english:"openSUSE Security Update : XEN (openSUSE-SU-2012:1573-1)");
  script_summary(english:"Check for the openSUSE-2012-812 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security update of XEN fixes various bugs and security issues.

  - Upstream patch 26088-xend-xml-filesize-check.patch

  - bnc#787163 - CVE-2012-4544: xen: Domain builder Out-of-
    memory due to malicious kernel/ramdisk (XSA 25)
    CVE-2012-4544-xsa25.patch

  - bnc#779212 - CVE-2012-4411: XEN / qemu: guest
    administrator can access qemu monitor console (XSA-19)
    CVE-2012-4411-xsa19.patch

  - bnc#786516 - CVE-2012-4535: xen: Timer overflow DoS
    vulnerability CVE-2012-4535-xsa20.patch

  - bnc#786518 - CVE-2012-4536: xen: pirq range check DoS
    vulnerability CVE-2012-4536-xsa21.patch

  - bnc#786517 - CVE-2012-4537: xen: Memory mapping failure
    DoS vulnerability CVE-2012-4537-xsa22.patch

  - bnc#786519 - CVE-2012-4538: xen: Unhooking empty PAE
    entries DoS vulnerability CVE-2012-4538-xsa23.patch

  - bnc#786520 - CVE-2012-4539: xen: Grant table hypercall
    infinite loop DoS vulnerability
    CVE-2012-4539-xsa24.patch

  - bnc#784087 - L3: Xen BUG at io_apic.c:129
    26102-x86-IOAPIC-legacy-not-first.patch

  - Upstream patches from Jan
    26054-x86-AMD-perf-ctr-init.patch
    26055-x86-oprof-hvm-mode.patch
    26056-page-alloc-flush-filter.patch
    26061-x86-oprof-counter-range.patch
    26062-ACPI-ERST-move-data.patch
    26063-x86-HPET-affinity-lock.patch
    26093-HVM-PoD-grant-mem-type.patch

  - Upstream patches from Jan
    25931-x86-domctl-iomem-mapping-checks.patch
    25952-x86-MMIO-remap-permissions.patch

-------------------------------------------------------------------
Mon Sep 24 16:41:58 CEST 2012 - ohering@suse.de

  - use BuildRequires: gcc46 only in sles11sp2 or 12.1 to
    fix build in 11.4

-------------------------------------------------------------------
Thu Sep 20 10:03:40 MDT 2012 - carnold@novell.com

  - Upstream patches from Jan
    25808-domain_create-return-value.patch
    25814-x86_64-set-debugreg-guest.patch
    25815-x86-PoD-no-bug-in-non-translated.patch
    25816-x86-hvm-map-pirq-range-check.patch
    25833-32on64-bogus-pt_base-adjust.patch
    25834-x86-S3-MSI-resume.patch
    25835-adjust-rcu-lock-domain.patch
    25836-VT-d-S3-MSI-resume.patch 25850-tmem-xsa-15-1.patch
    25851-tmem-xsa-15-2.patch 25852-tmem-xsa-15-3.patch
    25853-tmem-xsa-15-4.patch 25854-tmem-xsa-15-5.patch
    25855-tmem-xsa-15-6.patch 25856-tmem-xsa-15-7.patch
    25857-tmem-xsa-15-8.patch 25858-tmem-xsa-15-9.patch
    25859-tmem-missing-break.patch 25860-tmem-cleanup.patch
    25883-pt-MSI-cleanup.patch
    25927-x86-domctl-ioport-mapping-range.patch
    25929-tmem-restore-pool-version.patch

  - bnc#778105 - first XEN-PV VM fails to spawn xend:
    Increase wait time for disk to appear in host bootloader
    Modified existing xen-domUloader.diff

  - Upstream patches from Jan
    25752-ACPI-pm-op-valid-cpu.patch
    25754-x86-PoD-early-access.patch
    25755-x86-PoD-types.patch
    25756-x86-MMIO-max-mapped-pfn.patch
    25757-x86-EPT-PoD-1Gb-assert.patch
    25764-x86-unknown-cpu-no-sysenter.patch
    25765-x86_64-allow-unsafe-adjust.patch
    25771-grant-copy-status-paged-out.patch
    25773-x86-honor-no-real-mode.patch
    25786-x86-prefer-multiboot-meminfo-over-e801.patch

  - bnc#777890 - CVE-2012-3497: xen: multiple TMEM hypercall
    vulnerabilities (XSA-15)
    CVE-2012-3497-tmem-xsa-15-1.patch
    CVE-2012-3497-tmem-xsa-15-2.patch
    CVE-2012-3497-tmem-xsa-15-3.patch
    CVE-2012-3497-tmem-xsa-15-4.patch
    CVE-2012-3497-tmem-xsa-15-5.patch
    CVE-2012-3497-tmem-xsa-15-6.patch
    CVE-2012-3497-tmem-xsa-15-7.patch
    CVE-2012-3497-tmem-xsa-15-8.patch
    CVE-2012-3497-tmem-xsa-15-9.patch
    tmem-missing-break.patch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-11/msg00085.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=764077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=771099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=778105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=784087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=786516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=786517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=786518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=786519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=786520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=787163"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected XEN packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/15");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"xen-debugsource-4.1.3_04-5.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-devel-4.1.3_04-5.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-default-4.1.3_04_k3.4.11_2.16-5.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-default-debuginfo-4.1.3_04_k3.4.11_2.16-5.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-desktop-4.1.3_04_k3.4.11_2.16-5.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-desktop-debuginfo-4.1.3_04_k3.4.11_2.16-5.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-pae-4.1.3_04_k3.4.11_2.16-5.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-pae-debuginfo-4.1.3_04_k3.4.11_2.16-5.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-libs-4.1.3_04-5.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-libs-debuginfo-4.1.3_04-5.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-tools-domU-4.1.3_04-5.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-tools-domU-debuginfo-4.1.3_04-5.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-4.1.3_04-5.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-doc-html-4.1.3_04-5.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-doc-pdf-4.1.3_04-5.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-libs-32bit-4.1.3_04-5.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.1.3_04-5.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-tools-4.1.3_04-5.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-tools-debuginfo-4.1.3_04-5.13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "XEN");
}
