#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-399.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(84012);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/06/08 17:19:25 $");

  script_cve_id("CVE-2015-1572");

  script_name(english:"openSUSE Security Update : e2fsprogs (openSUSE-2015-399)");
  script_summary(english:"Check for the openSUSE-2015-399 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"e2fsprogs was updated to fix one security issue.

The following vulnerability was fixed :

  - CVE-2015-1572: A local user could have executed
    arbitrary code by causing a crafted block group
    descriptor to be marked as dirty. (boo#918346)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=918346"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected e2fsprogs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:e2fsprogs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:e2fsprogs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:e2fsprogs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:e2fsprogs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:e2fsprogs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcom_err-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcom_err-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcom_err2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcom_err2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcom_err2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcom_err2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libext2fs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libext2fs-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libext2fs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libext2fs2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libext2fs2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libext2fs2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/08");
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

if ( rpm_check(release:"SUSE13.2", reference:"e2fsprogs-1.42.12-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"e2fsprogs-debuginfo-1.42.12-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"e2fsprogs-debugsource-1.42.12-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"e2fsprogs-devel-1.42.12-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcom_err-devel-1.42.12-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcom_err2-1.42.12-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcom_err2-debuginfo-1.42.12-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libext2fs-devel-1.42.12-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libext2fs2-1.42.12-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libext2fs2-debuginfo-1.42.12-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"e2fsprogs-debuginfo-32bit-1.42.12-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libcom_err-devel-32bit-1.42.12-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libcom_err2-32bit-1.42.12-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libcom_err2-debuginfo-32bit-1.42.12-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libext2fs-devel-32bit-1.42.12-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libext2fs2-32bit-1.42.12-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libext2fs2-debuginfo-32bit-1.42.12-7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "e2fsprogs / e2fsprogs-debuginfo / e2fsprogs-debuginfo-32bit / etc");
}
