#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-169.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74910);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_name(english:"openSUSE Security Update : PackageKit (openSUSE-SU-2013:0381-1)");
  script_summary(english:"Check for the openSUSE-2013-169 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"PackageKit was fixed to add a patch to forbid update to downgrade
(bnc#804983)

As the update operation is allowed for logged in regular users, they
could install old package versions which might have been still
affected by already fixed security problems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-03/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804983"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected PackageKit packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-14-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-14-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-14-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-qt2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-qt2-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-qt2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-qt2-2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-qt2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-qt2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-PackageKitGlib-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-PackageKitPlugin-1_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/22");
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

if ( rpm_check(release:"SUSE12.2", reference:"PackageKit-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"PackageKit-backend-zypp-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"PackageKit-backend-zypp-debuginfo-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"PackageKit-branding-upstream-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"PackageKit-browser-plugin-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"PackageKit-browser-plugin-debuginfo-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"PackageKit-debuginfo-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"PackageKit-debugsource-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"PackageKit-devel-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"PackageKit-devel-debuginfo-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"PackageKit-gstreamer-plugin-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"PackageKit-gstreamer-plugin-debuginfo-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"PackageKit-gtk3-module-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"PackageKit-gtk3-module-debuginfo-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"PackageKit-lang-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpackagekit-glib2-14-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpackagekit-glib2-14-debuginfo-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpackagekit-glib2-devel-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpackagekit-qt2-2-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpackagekit-qt2-2-debuginfo-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpackagekit-qt2-devel-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"typelib-1_0-PackageKitGlib-1_0-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"typelib-1_0-PackageKitPlugin-1_0-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libpackagekit-glib2-14-32bit-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libpackagekit-glib2-14-debuginfo-32bit-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libpackagekit-glib2-devel-32bit-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libpackagekit-qt2-2-32bit-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libpackagekit-qt2-2-debuginfo-32bit-0.7.4-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libpackagekit-qt2-devel-32bit-0.7.4-2.21.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PackageKit");
}
