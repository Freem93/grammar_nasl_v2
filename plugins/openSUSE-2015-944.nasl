#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-944.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87663);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/30 14:28:48 $");

  script_name(english:"openSUSE Security Update : glibc (openSUSE-2015-944)");
  script_summary(english:"Check for the openSUSE-2015-944 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"glibc was updated to fix one minor security issue and two bugs.

The following vulnerability was fixed :

  - boo#950944: pointer guarding weakness

The following bugs were fixed :

  - boo#955644: resource leak in resolver

  - boo#936251: bits/time.h misses CLOCK_TAI that is present
    in linux/time.h"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=936251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=950944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=955647"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-obsolete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-obsolete-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/30");
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

if ( rpm_check(release:"SUSE13.2", reference:"glibc-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-debuginfo-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-debugsource-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-devel-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-devel-debuginfo-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-devel-static-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-extra-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-extra-debuginfo-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-html-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-i18ndata-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-info-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-locale-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-locale-debuginfo-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-obsolete-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-obsolete-debuginfo-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-profile-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-utils-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-utils-debuginfo-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-utils-debugsource-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nscd-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nscd-debuginfo-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-utils-32bit-2.19-16.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-utils-debuginfo-32bit-2.19-16.18.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc-utils / glibc-utils-32bit / glibc-utils-debuginfo / etc");
}
