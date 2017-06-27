#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-243.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74606);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-0029");

  script_name(english:"openSUSE Security Update : Xen (openSUSE-SU-2012:0548-1)");
  script_summary(english:"Check for the openSUSE-2012-243 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is a XEN bugfix update fixing lots of bugs and one security
issue.

CVE-2012-0029: Heap-based buffer overflow in the process_tx_desc
function in the e1000 emulation (hw/e1000.c) in qemu-kvm 0.12, and
possibly other versions, allows guest OS users to cause a denial of
service (QEMU crash) and possibly execute arbitrary code via crafted
legacy mode packets."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-04/msg00055.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=740165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=743414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=753165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/310510"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected Xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtinst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virt-manager");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/15");
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

if ( rpm_check(release:"SUSE12.1", reference:"python-virtinst-0.600.1-4.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virt-manager-0.9.1-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-debugsource-4.1.2_16-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-devel-4.1.2_16-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-kmp-default-4.1.2_16_k3.1.9_1.4-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-kmp-default-debuginfo-4.1.2_16_k3.1.9_1.4-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-kmp-desktop-4.1.2_16_k3.1.9_1.4-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-kmp-desktop-debuginfo-4.1.2_16_k3.1.9_1.4-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-kmp-pae-4.1.2_16_k3.1.9_1.4-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-kmp-pae-debuginfo-4.1.2_16_k3.1.9_1.4-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-libs-4.1.2_16-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-libs-debuginfo-4.1.2_16-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-tools-domU-4.1.2_16-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xen-tools-domU-debuginfo-4.1.2_16-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-4.1.2_16-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-doc-html-4.1.2_16-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-doc-pdf-4.1.2_16-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-libs-32bit-4.1.2_16-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.1.2_16-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-tools-4.1.2_16-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xen-tools-debuginfo-4.1.2_16-1.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Xen");
}
