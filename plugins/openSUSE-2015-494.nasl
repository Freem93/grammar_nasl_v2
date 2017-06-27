#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-494.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(84816);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2015/09/13 04:38:20 $");

  script_cve_id("CVE-2014-8500", "CVE-2015-1349", "CVE-2015-4620");

  script_name(english:"openSUSE Security Update : bind (openSUSE-2015-494)");
  script_summary(english:"Check for the openSUSE-2015-494 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"bind was updated to fix three security issues.

These security issues were fixed :

  - CVE-2015-1349: named in ISC BIND 9.7.0 through 9.9.6
    before 9.9.6-P2 and 9.10.x before 9.10.1-P2, when DNSSEC
    validation and the managed-keys feature are enabled,
    allowed remote attackers to cause a denial of service
    (assertion failure and daemon exit, or daemon crash) by
    triggering an incorrect trust-anchor management scenario
    in which no key is ready for use (bsc#918330).

  - CVE-2014-8500: ISC BIND 9.0.x through 9.8.x, 9.9.0
    through 9.9.6, and 9.10.0 through 9.10.1 did not limit
    delegation chaining, which allowed remote attackers to
    cause a denial of service (memory consumption and named
    crash) via a large or infinite number of referrals
    (bsc#908994).

  - CVE-2015-4620: Resolver crash when validating
    (bsc#936476)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=918330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=936476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937028"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/17");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"bind-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-chrootenv-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-debuginfo-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-debugsource-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-devel-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-libs-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-libs-debuginfo-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-lwresd-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-lwresd-debuginfo-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-utils-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-utils-debuginfo-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"bind-libs-32bit-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"bind-libs-debuginfo-32bit-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-9.9.6P1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-chrootenv-9.9.6P1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-debuginfo-9.9.6P1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-debugsource-9.9.6P1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-devel-9.9.6P1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-libs-9.9.6P1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-libs-debuginfo-9.9.6P1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-lwresd-9.9.6P1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-lwresd-debuginfo-9.9.6P1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-utils-9.9.6P1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bind-utils-debuginfo-9.9.6P1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"bind-libs-32bit-9.9.6P1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"bind-libs-debuginfo-32bit-9.9.6P1-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chrootenv / bind-debuginfo / bind-debugsource / etc");
}
