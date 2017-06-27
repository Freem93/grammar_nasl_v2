#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-700.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91555);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2016-5118");

  script_name(english:"openSUSE Security Update : ImageMagick (openSUSE-2016-700)");
  script_summary(english:"Check for the openSUSE-2016-700 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ImageMagick fixes the following issues :

  - security update :

  - CVE-2016-5118 [boo#982178]

  + ImageMagick-CVE-2016-5118.patch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982178"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ImageMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PerlMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PerlMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/10");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"ImageMagick-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ImageMagick-debuginfo-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ImageMagick-debugsource-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ImageMagick-devel-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ImageMagick-extra-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ImageMagick-extra-debuginfo-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagick++-6_Q16-5-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagick++-6_Q16-5-debuginfo-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagick++-devel-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagickCore-6_Q16-2-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagickCore-6_Q16-2-debuginfo-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagickWand-6_Q16-2-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagickWand-6_Q16-2-debuginfo-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-PerlMagick-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-PerlMagick-debuginfo-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"ImageMagick-devel-32bit-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagick++-6_Q16-5-32bit-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagick++-6_Q16-5-debuginfo-32bit-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagick++-devel-32bit-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagickCore-6_Q16-2-32bit-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagickCore-6_Q16-2-debuginfo-32bit-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagickWand-6_Q16-2-32bit-6.8.9.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagickWand-6_Q16-2-debuginfo-32bit-6.8.9.8-21.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-debuginfo / ImageMagick-debugsource / etc");
}
