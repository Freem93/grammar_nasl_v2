#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-598.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74751);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-2625", "CVE-2012-3432", "CVE-2012-3433", "CVE-2012-3494", "CVE-2012-3495", "CVE-2012-3496", "CVE-2012-3498", "CVE-2012-3515");

  script_name(english:"openSUSE Security Update : Xen (openSUSE-SU-2012:1176-1)");
  script_summary(english:"Check for the openSUSE-2012-598 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(attribute:"description", value:"Security Update for Xen");
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-09/msg00063.html"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=766284"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"xen-debugsource-4.1.3_01-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-devel-4.1.3_01-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-default-4.1.3_01_k3.4.6_2.10-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-default-debuginfo-4.1.3_01_k3.4.6_2.10-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-desktop-4.1.3_01_k3.4.6_2.10-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-desktop-debuginfo-4.1.3_01_k3.4.6_2.10-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-pae-4.1.3_01_k3.4.6_2.10-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-pae-debuginfo-4.1.3_01_k3.4.6_2.10-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-libs-4.1.3_01-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-libs-debuginfo-4.1.3_01-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-tools-domU-4.1.3_01-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-tools-domU-debuginfo-4.1.3_01-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-4.1.3_01-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-doc-html-4.1.3_01-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-doc-pdf-4.1.3_01-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-libs-32bit-4.1.3_01-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.1.3_01-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-tools-4.1.3_01-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-tools-debuginfo-4.1.3_01-5.6.2") ) flag++;

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
