#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1200.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94128);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/03 14:55:09 $");

  script_cve_id("CVE-2016-7966");

  script_name(english:"openSUSE Security Update : kcoreaddons (openSUSE-2016-1200)");
  script_summary(english:"Check for the openSUSE-2016-1200 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for kcoreaddons fixes the following issues :

  - CVE-2016-7966: HTML injection in plain text viewer
    (boo#1002977)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002977"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kcoreaddons packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kcoreaddons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kcoreaddons-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kcoreaddons-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kcoreaddons-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kcoreaddons-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kcoreaddons-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kcoreaddons-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libKF5CoreAddons5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libKF5CoreAddons5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libKF5CoreAddons5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libKF5CoreAddons5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/19");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"kcoreaddons-5.11.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kcoreaddons-debugsource-5.11.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kcoreaddons-devel-5.11.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kcoreaddons-devel-debuginfo-5.11.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kcoreaddons-lang-5.11.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libKF5CoreAddons5-5.11.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libKF5CoreAddons5-debuginfo-5.11.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kcoreaddons-devel-32bit-5.11.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kcoreaddons-devel-debuginfo-32bit-5.11.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libKF5CoreAddons5-32bit-5.11.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libKF5CoreAddons5-debuginfo-32bit-5.11.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kcoreaddons-5.21.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kcoreaddons-debugsource-5.21.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kcoreaddons-devel-5.21.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kcoreaddons-devel-debuginfo-5.21.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kcoreaddons-lang-5.21.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libKF5CoreAddons5-5.21.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libKF5CoreAddons5-debuginfo-5.21.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kcoreaddons-devel-32bit-5.21.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kcoreaddons-devel-debuginfo-32bit-5.21.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libKF5CoreAddons5-32bit-5.21.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libKF5CoreAddons5-debuginfo-32bit-5.21.0-18.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kcoreaddons / kcoreaddons-debugsource / kcoreaddons-devel-32bit / etc");
}
