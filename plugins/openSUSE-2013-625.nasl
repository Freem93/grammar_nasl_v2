#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-625.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75103);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-4132", "CVE-2013-4133");

  script_name(english:"openSUSE Security Update : kdebase4-workspace (openSUSE-SU-2013:1291-1)");
  script_summary(english:"Check for the openSUSE-2013-625 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"kdebase4-workspace received fixes for :

  - KDM: a potential crash in crypt() was fixed (bnc#829857,
    CVE-2013-4132)

  - Fixes plasma systemtray memory leak with legacy icons
    (kde#314919, bnc#817932, bnc#829857, CVE-2013-4133)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-08/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829857"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdebase4-workspace packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-plasma-engine-akonadi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-plasma-engine-akonadi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdm-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kwin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kwin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-kdebase4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"kde4-kgreeter-plugins-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kde4-kgreeter-plugins-debuginfo-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kdebase4-workspace-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kdebase4-workspace-branding-upstream-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kdebase4-workspace-debuginfo-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kdebase4-workspace-debugsource-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kdebase4-workspace-devel-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kdebase4-workspace-devel-debuginfo-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kdebase4-workspace-ksysguardd-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kdebase4-workspace-ksysguardd-debuginfo-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kdebase4-workspace-liboxygenstyle-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kdebase4-workspace-liboxygenstyle-debuginfo-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kdebase4-workspace-plasma-calendar-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kdebase4-workspace-plasma-calendar-debuginfo-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kdebase4-workspace-plasma-engine-akonadi-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kdebase4-workspace-plasma-engine-akonadi-debuginfo-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kdm-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kdm-branding-upstream-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kdm-debuginfo-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kwin-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kwin-debuginfo-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"python-kdebase4-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kdebase4-workspace-liboxygenstyle-32bit-4.8.5-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kdebase4-workspace-liboxygenstyle-debuginfo-32bit-4.8.5-2.18.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdebase4-workspace");
}
