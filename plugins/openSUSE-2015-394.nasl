#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-394.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(83982);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/11/05 16:11:32 $");

  script_cve_id("CVE-2015-3202");

  script_name(english:"openSUSE Security Update : fuse (openSUSE-2015-394)");
  script_summary(english:"Check for the openSUSE-2015-394 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Update to version 2.9.4

  - fix exec environment for mount and umount (bsc#931452,
    CVE-2015-3202)

  - properly restore the default signal handler

  - fix directory file handle passed to&#9;ioctl() method.

  - fix for uids/gids larger than 2147483647

  - initialize stat buffer passed to getattr() and
    fgetattr()"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931452"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected fuse packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fuse-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fuse-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fuse-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfuse2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfuse2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfuse2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfuse2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libulockmgr1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libulockmgr1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/04");
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

if ( rpm_check(release:"SUSE13.2", reference:"fuse-2.9.4-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"fuse-debuginfo-2.9.4-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"fuse-debugsource-2.9.4-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"fuse-devel-2.9.4-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"fuse-devel-static-2.9.4-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfuse2-2.9.4-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfuse2-debuginfo-2.9.4-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libulockmgr1-2.9.4-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libulockmgr1-debuginfo-2.9.4-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libfuse2-32bit-2.9.4-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libfuse2-debuginfo-32bit-2.9.4-4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fuse / fuse-debuginfo / fuse-debugsource / fuse-devel / etc");
}
