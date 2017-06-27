#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-399.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74986);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:13 $");

  script_cve_id("CVE-2013-1764");

  script_name(english:"openSUSE Security Update : PackageKit (openSUSE-SU-2013:0889-1)");
  script_summary(english:"Check for the openSUSE-2013-399 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The PackageKit zypp backend was fixed to only allow patches to be
updated. Otherwise a regular user could install new packages or even
downgrade older packages to ones with security problems.
(CVE-2013-1764)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804983"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected PackageKit packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-backend-zypp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-backend-zypp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-browser-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-gstreamer-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-gstreamer-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-gtk3-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-gtk3-module-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-16-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-16-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-16-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-PackageKitGlib-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-PackageKitPlugin-1_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/14");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"PackageKit-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"PackageKit-backend-zypp-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"PackageKit-backend-zypp-debuginfo-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"PackageKit-branding-upstream-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"PackageKit-browser-plugin-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"PackageKit-browser-plugin-debuginfo-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"PackageKit-debuginfo-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"PackageKit-debugsource-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"PackageKit-devel-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"PackageKit-devel-debuginfo-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"PackageKit-gstreamer-plugin-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"PackageKit-gstreamer-plugin-debuginfo-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"PackageKit-gtk3-module-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"PackageKit-gtk3-module-debuginfo-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"PackageKit-lang-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpackagekit-glib2-16-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpackagekit-glib2-16-debuginfo-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpackagekit-glib2-devel-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"typelib-1_0-PackageKitGlib-1_0-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"typelib-1_0-PackageKitPlugin-1_0-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libpackagekit-glib2-16-32bit-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libpackagekit-glib2-16-debuginfo-32bit-0.8.7-4.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libpackagekit-glib2-devel-32bit-0.8.7-4.8.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PackageKit");
}
