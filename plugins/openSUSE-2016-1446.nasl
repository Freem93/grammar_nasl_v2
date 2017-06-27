#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1446.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95752);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/18 13:37:17 $");

  script_cve_id("CVE-2016-5011");

  script_name(english:"openSUSE Security Update : util-linux (openSUSE-2016-1446)");
  script_summary(english:"Check for the openSUSE-2016-1446 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for util-linux fixes the following issues :

  - Consider redundant slashes when comparing paths
    (bsc#982331,
    util-linux-libmount-ignore-redundant-slashes.patch,
    affects backport of
    util-linux-libmount-cifs-is_mounted.patch).

  - Use upstream compatibility patches for
    --show-pt-geometry with obsolescence and deprecation
    warning (bsc#990531)

  - Replace cifs mount detection patch with upstream one
    that covers all cases (bsc#987176).

  - Reuse existing loop device to prevent possible data
    corruption when multiple -o loop are used to mount a
    single file (bsc#947494)

  - Safe loop re-use in libmount, mount and losetup
    (bsc#947494)

  - UPSTREAM DIVERGENCE!!! losetup -L continues to use SLE12
    SP1 and SP2 specific meaning

    --logical-blocksize instead of upstream --nooverlap
    (bsc#966891).

  - Make release-dependent conflict with old sysvinit-tools
    SLE specific, as it is required only for SLE 11 upgrade,
    and breaks openSUSE staging builds (bsc#994399).

  - Extended partition loop in MBR partition table leads to
    DoS (bsc#988361, CVE-2016-5011)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=947494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988361"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994399"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected util-linux packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libmount-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libmount-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uuidd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uuidd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/13");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libblkid-devel-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libblkid-devel-static-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libblkid1-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libblkid1-debuginfo-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libfdisk-devel-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libfdisk-devel-static-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libfdisk1-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libfdisk1-debuginfo-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmount-devel-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmount-devel-static-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmount1-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmount1-debuginfo-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsmartcols-devel-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsmartcols-devel-static-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsmartcols1-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsmartcols1-debuginfo-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libuuid-devel-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libuuid-devel-static-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libuuid1-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libuuid1-debuginfo-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-libmount-2.28-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-libmount-debuginfo-2.28-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-libmount-debugsource-2.28-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"util-linux-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"util-linux-debuginfo-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"util-linux-debugsource-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"util-linux-lang-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"util-linux-systemd-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"util-linux-systemd-debuginfo-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"util-linux-systemd-debugsource-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"uuidd-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"uuidd-debuginfo-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libblkid-devel-32bit-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libblkid1-32bit-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libblkid1-debuginfo-32bit-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmount-devel-32bit-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmount1-32bit-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmount1-debuginfo-32bit-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libuuid-devel-32bit-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libuuid1-32bit-2.28-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libuuid1-debuginfo-32bit-2.28-7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-libmount / python-libmount-debuginfo / etc");
}
