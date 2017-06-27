#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-893.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87443);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/17 15:21:31 $");

  script_cve_id("CVE-2015-5307", "CVE-2015-7311", "CVE-2015-7835", "CVE-2015-7970", "CVE-2015-8104");

  script_name(english:"openSUSE Security Update : xen (openSUSE-2015-893)");
  script_summary(english:"Check for the openSUSE-2015-893 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following security issues :

  - bsc#947165 - CVE-2015-7311: xen: libxl fails to honour
    readonly flag on disks with qemu-xen (xsa-142)

  - bsc#954405 - CVE-2015-8104: Xen: guest to host DoS by
    triggering an infinite loop in microcode via #DB
    exception

  - bsc#954018 - CVE-2015-5307: xen: x86: CPU lockup during
    fault delivery (XSA-156)

  - bsc#950704 - CVE-2015-7970: xen: x86: Long latency
    populate-on-demand operation is not preemptible
    (XSA-150)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=947165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=950704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954405"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"xen-debugsource-4.4.3_04-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-devel-4.4.3_04-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-libs-4.4.3_04-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-libs-debuginfo-4.4.3_04-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-tools-domU-4.4.3_04-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-tools-domU-debuginfo-4.4.3_04-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-4.4.3_04-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-doc-html-4.4.3_04-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-default-4.4.3_04_k3.16.7_29-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.4.3_04_k3.16.7_29-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-desktop-4.4.3_04_k3.16.7_29-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-desktop-debuginfo-4.4.3_04_k3.16.7_29-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-libs-32bit-4.4.3_04-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.4.3_04-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-tools-4.4.3_04-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-tools-debuginfo-4.4.3_04-33.1") ) flag++;

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
