#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update mozilla-xulrunner191-4202.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(53778);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/06/13 20:00:37 $");

  script_name(english:"openSUSE Security Update : mozilla-xulrunner191 (mozilla-xulrunner191-4202)");
  script_summary(english:"Check for the mozilla-xulrunner191-4202 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla XULRunner 1.9.1 was updated to version 1.9.1.18 to fix the
following security issue :

MFSA 2011-11 Several invalid HTTPS certificates were placed on the
certificate blacklist to prevent their misuse."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=680771"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla-xulrunner191 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-gnomevfs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-xpcom191");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-1.9.1.18-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-devel-1.9.1.18-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.18-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-translations-common-1.9.1.18-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-translations-other-1.9.1.18-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"python-xpcom191-1.9.1.18-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.18-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-32bit-1.9.1.18-0.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-xulrunner191 / mozilla-xulrunner191-32bit / etc");
}
