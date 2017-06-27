#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-322.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(89855);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/13 14:27:28 $");

  script_cve_id("CVE-2016-2851");

  script_name(english:"openSUSE Security Update : libotr / libotr2 (openSUSE-2016-322)");
  script_summary(english:"Check for the openSUSE-2016-322 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libotr and libotr2 were updated to fix one security issue :

  - CVE-2016-2851: Integer overflow vulnerability allowed
    remote attackers to execute arbitrary code on 64 bit
    platforms (boo#969785)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969785"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libotr / libotr2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libotr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libotr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libotr-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libotr-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libotr2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libotr2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libotr2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libotr2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libotr2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libotr2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libotr5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libotr5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libotr-debugsource-4.0.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libotr-devel-4.0.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libotr-tools-4.0.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libotr-tools-debuginfo-4.0.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libotr2-3.2.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libotr2-debuginfo-3.2.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libotr2-debugsource-3.2.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libotr2-devel-3.2.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libotr2-tools-3.2.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libotr2-tools-debuginfo-3.2.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libotr5-4.0.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libotr5-debuginfo-4.0.0-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libotr-debugsource-4.1.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libotr-devel-4.1.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libotr-tools-4.1.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libotr-tools-debuginfo-4.1.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libotr2-3.2.1-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libotr2-debuginfo-3.2.1-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libotr2-debugsource-3.2.1-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libotr2-devel-3.2.1-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libotr2-tools-3.2.1-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libotr2-tools-debuginfo-3.2.1-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libotr5-4.1.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libotr5-debuginfo-4.1.1-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libotr-debugsource / libotr-devel / libotr-tools / etc");
}
