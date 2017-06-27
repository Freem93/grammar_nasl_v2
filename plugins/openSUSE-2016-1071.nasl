#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1071.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93434);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2016-6352");

  script_name(english:"openSUSE Security Update : gdk-pixbuf (openSUSE-2016-1071)");
  script_summary(english:"Check for the openSUSE-2016-1071 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"gdk-pixbuf was updated to 2.32.3 to fix the following issues :

Update to version 2.32.3 :

  + Fix two crashes in the bmp loader (bgo#747605,
    bgo#758991)

  + ico: integer overflow fixes

  + Avoid some integer overflow possibilities in scaling
    code

  + Make relocations optional

  + Fix a crash due to overflow when scaling

  + Drop loaders for some rare image formats: wbmp, ras, pcx

  + Prevent testsuite failures due to lack of memory

  + Fix animation loading (bgo#755269)

  + More overflow fixes in the scaling code (bgo#754387)

  + Fix a crash in the tga loader

  + Fix several integer overflows (bgo#753908, bgo#753569)

  + Port animations to GTask

  + Translation updates

  - Add fixes for some crashes, taken from upstream git
    (boo#988745 boo#991450 CVE-2016-6352) :"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991450"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gdk-pixbuf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-query-loaders");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-query-loaders-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-query-loaders-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-query-loaders-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdk_pixbuf-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdk_pixbuf-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdk_pixbuf-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdk_pixbuf-2_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GdkPixbuf-2_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/12");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"gdk-pixbuf-debugsource-2.32.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gdk-pixbuf-devel-2.32.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gdk-pixbuf-devel-debuginfo-2.32.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gdk-pixbuf-lang-2.32.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gdk-pixbuf-query-loaders-2.32.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gdk-pixbuf-query-loaders-debuginfo-2.32.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgdk_pixbuf-2_0-0-2.32.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgdk_pixbuf-2_0-0-debuginfo-2.32.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-GdkPixbuf-2_0-2.32.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gdk-pixbuf-devel-32bit-2.32.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gdk-pixbuf-devel-debuginfo-32bit-2.32.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gdk-pixbuf-query-loaders-32bit-2.32.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gdk-pixbuf-query-loaders-debuginfo-32bit-2.32.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgdk_pixbuf-2_0-0-32bit-2.32.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgdk_pixbuf-2_0-0-debuginfo-32bit-2.32.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gdk-pixbuf-debugsource-2.32.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gdk-pixbuf-devel-2.32.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gdk-pixbuf-devel-debuginfo-2.32.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gdk-pixbuf-lang-2.32.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gdk-pixbuf-query-loaders-2.32.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gdk-pixbuf-query-loaders-debuginfo-2.32.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgdk_pixbuf-2_0-0-2.32.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgdk_pixbuf-2_0-0-debuginfo-2.32.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"typelib-1_0-GdkPixbuf-2_0-2.32.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gdk-pixbuf-devel-32bit-2.32.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gdk-pixbuf-devel-debuginfo-32bit-2.32.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gdk-pixbuf-query-loaders-32bit-2.32.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gdk-pixbuf-query-loaders-debuginfo-32bit-2.32.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgdk_pixbuf-2_0-0-32bit-2.32.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgdk_pixbuf-2_0-0-debuginfo-32bit-2.32.3-8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdk-pixbuf-debugsource / gdk-pixbuf-devel / gdk-pixbuf-devel-32bit / etc");
}
