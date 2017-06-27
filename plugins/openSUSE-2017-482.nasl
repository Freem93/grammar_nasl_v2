#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-482.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99450);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/19 13:27:09 $");

  script_cve_id("CVE-2016-8637");

  script_name(english:"openSUSE Security Update : dracut (openSUSE-2017-482)");
  script_summary(english:"Check for the openSUSE-2017-482 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for dracut fixes the following issues :

Security issues fixed :

  - CVE-2016-8637: When the early microcode loading was
    enabled during initrd creation, the initrd would be
    read-only available for all users, allowing local users
    to retrieve secrets stored in the initial ramdisk.
    (bsc#1008340)

Non security issues fixed :

  - Remove zlib module as requirement. (bsc#1020063)

  - Unlimit TaskMax for xfs_repair in emergency shell.
    (bsc#1019938)

  - Resolve symbolic links for -i and -k parameters.
    (bsc#902375)

  - Enhance purge-kernels script to handle kgraft patches.
    (bsc#1017141)

  - Allow booting from degraded MD arrays with systemd.
    (bsc#1017695)

  - Allow booting on s390x with fips=1 on the kernel command
    line. (bnc#1021687)

  - Start multipath services before local-fs-pre.target.
    (bsc#1005410, bsc#1006118, bsc#1007925)

  - Fix /sbin/installkernel to handle kernel packages built
    with 'make bin-rpmpkg'. (bsc#1008648)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dracut packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dracut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dracut-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dracut-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dracut-fips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dracut-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"dracut-044-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dracut-debuginfo-044-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dracut-debugsource-044-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dracut-fips-044-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dracut-tools-044-16.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dracut / dracut-debuginfo / dracut-debugsource / dracut-fips / etc");
}
