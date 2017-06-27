#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1272.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94619);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/23 17:47:51 $");

  script_cve_id("CVE-2016-8864");

  script_name(english:"openSUSE Security Update : bind (openSUSE-2016-1272)");
  script_summary(english:"Check for the openSUSE-2016-1272 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for bind fixes the following issues :

  - A defect in BIND's handling of responses containing a
    DNAME answer had the potential to trigger assertion
    errors in the server remotely, thereby facilitating a
    denial-of-service attack. (CVE-2016-8864, bsc#1007829)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007829"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-chrootenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-lwresd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-lwresd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.2", reference:"bind-9.9.6P1-2.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-chrootenv-9.9.6P1-2.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-debuginfo-9.9.6P1-2.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-debugsource-9.9.6P1-2.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-devel-9.9.6P1-2.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-libs-9.9.6P1-2.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-libs-debuginfo-9.9.6P1-2.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-lwresd-9.9.6P1-2.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-lwresd-debuginfo-9.9.6P1-2.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-utils-9.9.6P1-2.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-utils-debuginfo-9.9.6P1-2.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"bind-libs-32bit-9.9.6P1-2.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"bind-libs-debuginfo-32bit-9.9.6P1-2.25.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chrootenv / bind-debuginfo / bind-debugsource / etc");
}
