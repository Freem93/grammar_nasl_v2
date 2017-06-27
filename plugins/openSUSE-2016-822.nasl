#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-822.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91942);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2016-4994");

  script_name(english:"openSUSE Security Update : gimp (openSUSE-2016-822)");
  script_summary(english:"Check for the openSUSE-2016-822 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"gimp was updated to version 2.8.16 to fix one security issue.

This security issue was fixed :

  - CVE-2016-4994: Use-after-free vulnerabilities in the
    channel and layer properties parsing process
    (bsc#986021).

This non-security issues were fixed :

  - Core :

  - Seek much less when writing XCF

  - Don't seek past the end of the file when writing XCF

  - Fix velocity parameter on .GIH brushes

  - Fix brokenness while transforming certain sets of linked
    layers

  - GUI :

  - Always show image tabs in single window mode

  - Fix switching of dock tabs by DND hovering

  - Don't make the scroll area for tags too small

  - Fixed a crash in the save dialog

  - Fix issue where ruler updates made things very slow on
    Windows

-Plug-ins :

  - Fix several issues in the BMP plug-in

  - Make Gfig work with the new brush size behavior again

  - Fix font export in the PDF plug-in

  - Support layer groups in OpenRaster files

  - Fix loading of PSD files with layer groups"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986021"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gimp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-help-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-help-browser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-plugin-aa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-plugin-aa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-plugins-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-plugins-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimp-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimp-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimp-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimp-2_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpui-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpui-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpui-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpui-2_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/05");
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

if ( rpm_check(release:"SUSE13.2", reference:"gimp-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gimp-debuginfo-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gimp-debugsource-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gimp-devel-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gimp-devel-debuginfo-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gimp-help-browser-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gimp-help-browser-debuginfo-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gimp-lang-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gimp-plugin-aa-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gimp-plugin-aa-debuginfo-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gimp-plugins-python-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gimp-plugins-python-debuginfo-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgimp-2_0-0-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgimp-2_0-0-debuginfo-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgimpui-2_0-0-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgimpui-2_0-0-debuginfo-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgimp-2_0-0-32bit-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgimp-2_0-0-debuginfo-32bit-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgimpui-2_0-0-32bit-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgimpui-2_0-0-debuginfo-32bit-2.8.16-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gimp-2.8.16-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gimp-debuginfo-2.8.16-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gimp-debugsource-2.8.16-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gimp-devel-2.8.16-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gimp-devel-debuginfo-2.8.16-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gimp-help-browser-2.8.16-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gimp-help-browser-debuginfo-2.8.16-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gimp-lang-2.8.16-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gimp-plugin-aa-2.8.16-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gimp-plugin-aa-debuginfo-2.8.16-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gimp-plugins-python-2.8.16-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gimp-plugins-python-debuginfo-2.8.16-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgimp-2_0-0-2.8.16-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgimp-2_0-0-debuginfo-2.8.16-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgimpui-2_0-0-2.8.16-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgimpui-2_0-0-debuginfo-2.8.16-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgimp-2_0-0-32bit-2.8.16-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgimp-2_0-0-debuginfo-32bit-2.8.16-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgimpui-2_0-0-32bit-2.8.16-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgimpui-2_0-0-debuginfo-32bit-2.8.16-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp / gimp-debuginfo / gimp-debugsource / gimp-devel / etc");
}
