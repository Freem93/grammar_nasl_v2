#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-340.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(83171);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/01 13:43:01 $");

  script_cve_id("CVE-2014-2977", "CVE-2014-2978");

  script_name(english:"openSUSE Security Update : DirectFB (openSUSE-2015-340)");
  script_summary(english:"Check for the openSUSE-2015-340 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"DirectFB was updated to fix two security issues.

The following vulnerabilities were fixed :

  - CVE-2014-2977: Multiple integer signedness errors could
    allow remote attackers to cause a denial of service
    (crash) and possibly execute arbitrary code via the
    Voodoo interface, which triggers a stack-based buffer
    overflow.

  - CVE-2014-2978: Remote attackers could cause a denial of
    service (crash) and possibly execute arbitrary code via
    the Voodoo interface, which triggers an out-of-bounds
    write."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=878345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=878349"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected DirectFB packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:DirectFB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:DirectFB-Mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:DirectFB-Mesa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:DirectFB-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:DirectFB-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:DirectFB-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:DirectFB-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:DirectFB-libSDL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:DirectFB-libSDL-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:DirectFB-libvncclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:DirectFB-libvncclient-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lib++dfb-1_7-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lib++dfb-1_7-5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lib++dfb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdirectfb-1_6-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdirectfb-1_6-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdirectfb-1_6-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdirectfb-1_6-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdirectfb-1_7-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdirectfb-1_7-5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdirectfb-1_7-5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdirectfb-1_7-5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/01");
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

if ( rpm_check(release:"SUSE13.1", reference:"DirectFB-1.6.3-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"DirectFB-Mesa-1.6.3-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"DirectFB-Mesa-debuginfo-1.6.3-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"DirectFB-debuginfo-1.6.3-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"DirectFB-debugsource-1.6.3-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"DirectFB-devel-1.6.3-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"DirectFB-libSDL-1.6.3-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"DirectFB-libSDL-debuginfo-1.6.3-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"DirectFB-libvncclient-1.6.3-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"DirectFB-libvncclient-debuginfo-1.6.3-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdirectfb-1_6-0-1.6.3-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdirectfb-1_6-0-debuginfo-1.6.3-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"DirectFB-devel-32bit-1.6.3-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdirectfb-1_6-0-32bit-1.6.3-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdirectfb-1_6-0-debuginfo-32bit-1.6.3-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"DirectFB-1.7.5-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"DirectFB-Mesa-1.7.5-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"DirectFB-Mesa-debuginfo-1.7.5-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"DirectFB-debuginfo-1.7.5-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"DirectFB-debugsource-1.7.5-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"DirectFB-devel-1.7.5-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"DirectFB-libSDL-1.7.5-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"DirectFB-libSDL-debuginfo-1.7.5-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"DirectFB-libvncclient-1.7.5-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"DirectFB-libvncclient-debuginfo-1.7.5-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"lib++dfb-1_7-5-1.7.5-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"lib++dfb-1_7-5-debuginfo-1.7.5-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"lib++dfb-devel-1.7.5-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdirectfb-1_7-5-1.7.5-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdirectfb-1_7-5-debuginfo-1.7.5-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"DirectFB-devel-32bit-1.7.5-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdirectfb-1_7-5-32bit-1.7.5-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdirectfb-1_7-5-debuginfo-32bit-1.7.5-3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "DirectFB / DirectFB-Mesa / DirectFB-Mesa-debuginfo / etc");
}
