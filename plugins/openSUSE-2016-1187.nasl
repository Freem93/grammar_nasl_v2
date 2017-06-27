#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1187.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94062);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/10/14 14:05:17 $");

  script_cve_id("CVE-2016-3622", "CVE-2016-3623", "CVE-2016-3945", "CVE-2016-3990", "CVE-2016-3991");

  script_name(english:"openSUSE Security Update : tiff (openSUSE-2016-1187)");
  script_summary(english:"Check for the openSUSE-2016-1187 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tiff fixes the following security issues :

  - CVE-2016-3622: Specially crafted TIFF images could
    trigger a crash in tiff2rgba (bsc#974449)

  - Various out-of-bound write vulnerabilities with
    unspecified impact (MSVR 35093, MSVR 35094, MSVR 35095,
    MSVR 35096, MSVR 35097, MSVR 35098)

  - CVE-2016-3623: Specially crafted TIFF images could
    trigger a crash in rgb2ycbcr (bsc#974618)

  - CVE-2016-3945: Specially crafted TIFF images could
    trigger a crash or allow for arbitrary command execution
    via tiff2rgba (bsc#974614)

  - CVE-2016-3990: Specially crafted TIFF images could
    trigger a crash or allow for arbitrary command execution
    (bsc#975069)

  - CVE-2016-3991: Specially crafted TIFF images could
    trigger a crash or allow for arbitrary command execution
    via the tiffcrop tool (bsc#975070)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975070"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tiff packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/14");
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

if ( rpm_check(release:"SUSE42.1", reference:"libtiff-devel-4.0.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtiff5-4.0.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtiff5-debuginfo-4.0.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tiff-4.0.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tiff-debuginfo-4.0.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tiff-debugsource-4.0.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtiff-devel-32bit-4.0.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtiff5-32bit-4.0.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtiff5-debuginfo-32bit-4.0.6-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff-devel-32bit / libtiff-devel / libtiff5-32bit / libtiff5 / etc");
}
