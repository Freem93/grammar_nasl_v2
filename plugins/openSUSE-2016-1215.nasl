#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1215.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94240);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/10/25 16:45:47 $");

  script_cve_id("CVE-2016-5759");

  script_name(english:"openSUSE Security Update : kdump (openSUSE-2016-1215)");
  script_summary(english:"Check for the openSUSE-2016-1215 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for kdump provides several fixes and enhancements :

  - Refresh kdumprd if /etc/hosts or /etc/nsswitch.conf is
    changed. (bsc#943214)

  - Add a separate systemd service to rebuild kdumprd at
    boot. (bsc#943214)

  - Improve network setup in the kdump environment by
    reading configuration from wicked by default (system
    configuration files are used as a fallback).
    (bsc#980328)

  - Use the last mount entry in kdump_get_mountpoints().
    (bsc#951844)

  - Remove 'notsc' from the kdump kernel command line.
    (bsc#973213)

  - Handle dump files with many program headers.
    (bsc#932339, bsc#970708)

  - Fall back to stat() if file type is DT_UNKNOWN.
    (bsc#964206)

  - Remove vm. sysctls from kdump initrd. (bsc#927451,
    bsc#987862)

  - Use the exit code of kexec, not that of 'local'.
    (bsc#984799)

  - Convert sysroot to a bind mount in kdump initrd.
    (bsc#976864)

  - Distinguish between Xenlinux (aka Xenified or SUSE) and
    pvops Xen kernels, as the latter can run on bare metal.
    (bsc#974270)

  - CVE-2016-5759: Use full path to dracut as argument to
    bash. (bsc#989972, bsc#990200)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=927451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=932339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=943214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974270"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=976864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987862"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990200"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdump packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdump-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/25");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"kdump-0.8.15-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kdump-debuginfo-0.8.15-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kdump-debugsource-0.8.15-27.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdump / kdump-debuginfo / kdump-debugsource");
}
