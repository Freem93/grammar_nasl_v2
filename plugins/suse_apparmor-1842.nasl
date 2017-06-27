#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update apparmor-1842.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27153);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 20:06:05 $");

  script_name(english:"openSUSE 10 Security Update : apparmor (apparmor-1842)");
  script_summary(english:"Check for the apparmor-1842 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes security problems in the AppArmor confinment
technology.

Since it adds new flags to the profile syntax, you likely should
review and adapt your profiles.

  - If a profile allowed unconfined execution ('ux') of a
    child binary it was possible to inject code via
    LD_PRELOAD or similar environment variables into this
    child binary and execute code without confiment.

    We have added new flag 'Ux' (and 'Px' for 'px') which
    makes the executed child clear the most critical
    environment variables (similar to setuid programs).
    Special care needs to be taken nevertheless that this
    interaction between parent and child programs can not be
    exploited in other ways to gain the rights of the child
    process.

  - If a resource is marked as 'r' in the profile it was
    possible to use mmap with PROT_EXEC flag set to load
    this resource as executable piece of code, making it
    effectively 'ix'.

    This could be used by a coordinated attack between two
    applications to potentially inject code into the reader.

    To allow mmap() executable access, supply the 'm' flag
    to the applications profile.

Please also review the updated documentation."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apparmor packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-admin_en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-profiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:audit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:audit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:audit-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yast2-apparmor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"apparmor-admin_en-10-7.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"apparmor-parser-2.0-21.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"apparmor-profiles-2.0-34.9") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"apparmor-utils-2.0-23.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"audit-1.1.3-23.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"audit-devel-1.1.3-23.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"audit-libs-1.1.3-23.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"yast2-apparmor-2.0-27.5") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "AppArmor");
}
