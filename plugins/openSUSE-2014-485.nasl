#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-485.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(77129);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/21 14:15:32 $");

  script_cve_id("CVE-2014-5033");

  script_name(english:"openSUSE Security Update : kdelibs4 (openSUSE-SU-2014:0981-1)");
  script_summary(english:"Check for the openSUSE-2014-485 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"KDE4 Libraries and Workspace received a security fix to fix a race
condition in DBUS/Polkit authorization, where local attackers could
potentially call root KDE services without proper authenticiation.
(CVE-2014-5033)

Additionaly a interlaced GIF display bug in KHTML was fixed.
(kde#330148)

This update also includes a kdebase4-workspace minor version update to
4.11.11 with various bugfixes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-08/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864716"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdelibs4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-kgreeter-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-kgreeter-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-ksysguardd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-ksysguardd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-liboxygenstyle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-liboxygenstyle-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-liboxygenstyle-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-liboxygenstyle-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-plasma-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-plasma-calendar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-doc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdm-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krandr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krandr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kwin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kwin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-kdebase4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"kde4-kgreeter-plugins-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kde4-kgreeter-plugins-debuginfo-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdebase4-workspace-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdebase4-workspace-branding-upstream-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdebase4-workspace-debuginfo-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdebase4-workspace-debugsource-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdebase4-workspace-devel-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdebase4-workspace-devel-debuginfo-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdebase4-workspace-ksysguardd-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdebase4-workspace-ksysguardd-debuginfo-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdebase4-workspace-liboxygenstyle-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdebase4-workspace-liboxygenstyle-debuginfo-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdebase4-workspace-plasma-calendar-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdebase4-workspace-plasma-calendar-debuginfo-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdelibs4-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdelibs4-apidocs-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdelibs4-branding-upstream-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdelibs4-core-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdelibs4-core-debuginfo-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdelibs4-debuginfo-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdelibs4-debugsource-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdelibs4-doc-debuginfo-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdm-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdm-branding-upstream-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdm-debuginfo-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"krandr-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"krandr-debuginfo-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kwin-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kwin-debuginfo-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libkde4-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libkde4-debuginfo-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libkde4-devel-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libkdecore4-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libkdecore4-debuginfo-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libkdecore4-devel-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libkdecore4-devel-debuginfo-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libksuseinstall-devel-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libksuseinstall1-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libksuseinstall1-debuginfo-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-kdebase4-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kdebase4-workspace-liboxygenstyle-32bit-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kdebase4-workspace-liboxygenstyle-debuginfo-32bit-4.11.11-115.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libkde4-32bit-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libkde4-debuginfo-32bit-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libkdecore4-32bit-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libkdecore4-debuginfo-32bit-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libksuseinstall1-32bit-4.11.5-484.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libksuseinstall1-debuginfo-32bit-4.11.5-484.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdelibs4");
}
