#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-303.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97562);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/28 13:31:42 $");

  script_cve_id("CVE-2016-10046", "CVE-2016-10048", "CVE-2016-10049", "CVE-2016-10050", "CVE-2016-10051", "CVE-2016-10052", "CVE-2016-10059", "CVE-2016-10060", "CVE-2016-10061", "CVE-2016-10062", "CVE-2016-10063", "CVE-2016-10064", "CVE-2016-10065", "CVE-2016-10068", "CVE-2016-10069", "CVE-2016-10070", "CVE-2016-10071", "CVE-2016-10144", "CVE-2016-10145", "CVE-2016-10146", "CVE-2016-9773", "CVE-2017-5506", "CVE-2017-5507", "CVE-2017-5508", "CVE-2017-5510", "CVE-2017-5511");

  script_name(english:"openSUSE Security Update : ImageMagick (openSUSE-2017-303)");
  script_summary(english:"Check for the openSUSE-2017-303 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ImageMagick fixes the following issues :

  - CVE-2016-10046: Prevent buffer overflow in draw.c caused
    by an incorrect length calculation (bsc#1017308)

  - CVE-2016-10048: Arbitrary module could have been load
    because relative path were not escaped (bsc#1017310)

  - CVE-2016-10049: Corrupt RLE files could have overflowed
    a buffer due to a incorrect length calculation
    (bsc#1017311)

  - CVE-2016-10050: Corrupt RLE files could have overflowed
    a heap buffer due to a missing offset check
    (bsc#1017312)

  - CVE-2016-10051: Fixed use after free when reading PWP
    files (bsc#1017313)

  - CVE-2016-10052: Added bound check to exif parsing of
    JPEG files (bsc#1017314)

  - CVE-2016-10059: Unchecked calculation when reading TIFF
    files could have lead to a buffer overflow (bsc#1017318)

  - CVE-2016-10060: Improved error handling when writing
    files to not mask errors (bsc#1017319)

  - CVE-2016-10061: Improved error handling when writing
    files to not mask errors (bsc#1017319).

  - CVE-2016-10062: Improved error handling when writing
    files to not mask errors (bsc#1017319).

  - CVE-2016-10063: Check validity of extend during TIFF
    file reading (bsc#1017320)

  - CVE-2016-10064: Improved checks for buffer overflow when
    reading TIFF files (bsc#1017321)

  - CVE-2016-10065: Unchecked calculations when reading VIFF
    files could have lead to out of bound reads
    (bsc#1017322)

  - CVE-2016-10068: Prevent NULL pointer access when using
    the MSL interpreter (bsc#1017324)

  - CVE-2016-10069: Add check for invalid mat file
    (bsc#1017325).

  - CVE-2016-10070: Prevent allocating the wrong amount of
    memory when reading mat files (bsc#1017326)

  - CVE-2016-10071: Prevent allocating the wrong amount of
    memory when reading mat files (bsc#1017326)

  - CVE-2016-10144: Added a check after allocating memory
    when parsing IPL files (bsc#1020433)

  - CVE-2016-10145: Fixed of-by-one in string copy operation
    when parsing WPG files (bsc#1020435)

  - CVE-2016-10146: Captions and labels were handled
    incorrectly, causing a memory leak that could have lead
    to DoS (bsc#1020443)

  - CVE-2017-5506: Missing offset check leading to a
    double-free (bsc#1020436)

  - CVE-2017-5507: Fixed a memory leak when reading MPC
    files allowing for DoS (bsc#1020439)

  - CVE-2017-5508: Increase the amount of memory allocated
    for TIFF pixels to prevent a heap buffer-overflow
    (bsc#1020441)

  - CVE-2017-5510: Prevent out-of-bounds write when reading
    PSD files (bsc#1020446).

  - CVE-2017-5511: A missing cast when reading PSD files
    could have caused memory corruption by a heap overflow
    (bsc#1020448)

This update removes the fix for CVE-2016-9773. ImageMagick-6 was not
affected by CVE-2016-9773 and it caused a regression (at least in
GraphicsMagick) (bsc#1017421).

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020448"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ImageMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PerlMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PerlMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"ImageMagick-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ImageMagick-debuginfo-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ImageMagick-debugsource-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ImageMagick-devel-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ImageMagick-extra-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ImageMagick-extra-debuginfo-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libMagick++-6_Q16-3-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libMagick++-6_Q16-3-debuginfo-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libMagick++-devel-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libMagickCore-6_Q16-1-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libMagickWand-6_Q16-1-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"perl-PerlMagick-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"perl-PerlMagick-debuginfo-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"ImageMagick-devel-32bit-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libMagick++-6_Q16-3-32bit-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libMagick++-6_Q16-3-debuginfo-32bit-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libMagick++-devel-32bit-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-32bit-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-32bit-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-32bit-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-debuginfo-32bit-6.8.8.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-debuginfo-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-debugsource-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-devel-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-extra-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-extra-debuginfo-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagick++-6_Q16-3-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagick++-6_Q16-3-debuginfo-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagick++-devel-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickCore-6_Q16-1-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickWand-6_Q16-1-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"perl-PerlMagick-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"perl-PerlMagick-debuginfo-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"ImageMagick-devel-32bit-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagick++-6_Q16-3-32bit-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagick++-6_Q16-3-debuginfo-32bit-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagick++-devel-32bit-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-32bit-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-32bit-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-32bit-6.8.8.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-debuginfo-32bit-6.8.8.1-28.1") ) flag++;

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
