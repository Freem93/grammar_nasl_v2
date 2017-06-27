#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-869.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74850);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2012-4535", "CVE-2012-4537", "CVE-2012-4538", "CVE-2012-5510", "CVE-2012-5511", "CVE-2012-5512", "CVE-2012-5513", "CVE-2012-5514", "CVE-2012-5515");

  script_name(english:"openSUSE Security Update : xen (openSUSE-SU-2012:1687-1)");
  script_summary(english:"Check for the openSUSE-2012-869 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"XEN was updated to fix various denial of service issues.

  - bnc#789945 - CVE-2012-5510: xen: Grant table version
    switch list corruption vulnerability (XSA-26)

  - bnc#789944 - CVE-2012-5511: xen: Several HVM operations
    do not validate the range of their inputs (XSA-27)

  - bnc#789940 - CVE-2012-5512: xen: HVMOP_get_mem_access
    crash / HVMOP_set_mem_access information leak (XSA-28)

  - bnc#789951 - CVE-2012-5513: xen: XENMEM_exchange may
    overwrite hypervisor memory (XSA-29)

  - bnc#789948 - CVE-2012-5514: xen: Missing unlock in
    guest_physmap_mark_populate_on_demand() (XSA-30)

  - bnc#789950 - CVE-2012-5515: xen: Several memory
    hypercall operations allow invalid extent order values
    (XSA-31)

  - bnc#789988 - FATAL PAGE FAULT in hypervisor
    (arch_do_domctl)

  - Upstream patches from Jan
    26132-tmem-save-NULL-check.patch
    26134-x86-shadow-invlpg-check.patch
    26148-vcpu-timer-overflow.patch (Replaces
    CVE-2012-4535-xsa20.patch)
    26149-x86-p2m-physmap-error-path.patch (Replaces
    CVE-2012-4537-xsa22.patch)
    26150-x86-shadow-unhook-toplevel-check.patch (Replaces
    CVE-2012-4538-xsa23.patch)

  - bnc#777628 - guest 'disappears' after live migration
    Updated block-dmmd script

  - Fix exception in balloon.py and osdep.py
    xen-max-free-mem.diff

  - bnc#792476 - efi files missing in latest XEN update
    Revert c/s 25751 EFI Makefile changes in
    23614-x86_64-EFI-boot.patch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-12/msg00048.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792476"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/07");
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

if ( rpm_check(release:"SUSE12.1", reference:"xen-debugsource-4.1.3_06-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-devel-4.1.3_06-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-kmp-default-4.1.3_06_k3.1.10_1.16-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-kmp-default-debuginfo-4.1.3_06_k3.1.10_1.16-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-kmp-desktop-4.1.3_06_k3.1.10_1.16-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-kmp-desktop-debuginfo-4.1.3_06_k3.1.10_1.16-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-kmp-pae-4.1.3_06_k3.1.10_1.16-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-kmp-pae-debuginfo-4.1.3_06_k3.1.10_1.16-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-libs-4.1.3_06-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-libs-debuginfo-4.1.3_06-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-tools-domU-4.1.3_06-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-tools-domU-debuginfo-4.1.3_06-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-4.1.3_06-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-doc-html-4.1.3_06-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-doc-pdf-4.1.3_06-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-libs-32bit-4.1.3_06-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.1.3_06-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-tools-4.1.3_06-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-tools-debuginfo-4.1.3_06-1.25.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
