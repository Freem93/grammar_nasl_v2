#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-825.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91945);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/03/27 13:24:14 $");

  script_cve_id("CVE-2014-9805", "CVE-2014-9807", "CVE-2014-9808", "CVE-2014-9809", "CVE-2014-9810", "CVE-2014-9811", "CVE-2014-9813", "CVE-2014-9814", "CVE-2014-9815", "CVE-2014-9816", "CVE-2014-9817", "CVE-2014-9818", "CVE-2014-9819", "CVE-2014-9820", "CVE-2014-9828", "CVE-2014-9829", "CVE-2014-9830", "CVE-2014-9831", "CVE-2014-9834", "CVE-2014-9835", "CVE-2014-9837", "CVE-2014-9839", "CVE-2014-9840", "CVE-2014-9844", "CVE-2014-9845", "CVE-2014-9846", "CVE-2014-9847", "CVE-2014-9853", "CVE-2015-8894", "CVE-2015-8896", "CVE-2015-8901", "CVE-2015-8903", "CVE-2016-2317", "CVE-2016-2318", "CVE-2016-5240", "CVE-2016-5241", "CVE-2016-5688");

  script_name(english:"openSUSE Security Update : GraphicsMagick (openSUSE-2016-825)");
  script_summary(english:"Check for the openSUSE-2016-825 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"GraphicsMagick was updated to fix 37 security issues.

These security issues were fixed :

  - CVE-2014-9810: SEGV in dpx file handler (bsc#983803).

  - CVE-2014-9811: Crash in xwd file handler (bsc#984032).

  - CVE-2014-9813: Crash on corrupted viff file
    (bsc#984035).

  - CVE-2014-9814: NULL pointer dereference in wpg file
    handling (bsc#984193).

  - CVE-2014-9815: Crash on corrupted wpg file (bsc#984372).

  - CVE-2014-9816: Out of bound access in viff image
    (bsc#984398).

  - CVE-2014-9817: Heap buffer overflow in pdb file handling
    (bsc#984400).

  - CVE-2014-9818: Out of bound access on malformed sun file
    (bsc#984181).

  - CVE-2014-9819: Heap overflow in palm files (bsc#984142).

  - CVE-2014-9830: Handling of corrupted sun file
    (bsc#984135).

  - CVE-2014-9831: Handling of corrupted wpg file
    (bsc#984375).

  - CVE-2014-9837: Additional PNM sanity checks
    (bsc#984166).

  - CVE-2014-9834: Heap overflow in pict file (bsc#984436).

  - CVE-2014-9853: Memory leak in rle file handling
    (bsc#984408).

  - CVE-2015-8903: Denial of service (cpu) in vicar
    (bsc#983259).

  - CVE-2015-8901: MIFF file DoS (endless loop)
    (bsc#983234).

  - CVE-2016-5688: Various invalid memory reads in
    ImageMagick WPG (bsc#985442).

  - CVE-2015-8894: Double free in coders/tga.c:221
    (bsc#983523).

  - CVE-2015-8896: Double free / integer truncation issue in
    coders/pict.c:2000 (bsc#983533).

  - CVE-2014-9807: Double free in pdb coder. (bsc#983794).

  - CVE-2014-9828: corrupted (too many colors) psd file
    (bsc#984028).

  - CVE-2014-9805: SEGV due to a corrupted pnm file.
    (bsc#983752).

  - CVE-2014-9808: SEGV due to corrupted dpc images.
    (bsc#983796).

  - CVE-2014-9820: Heap overflow in xpm files (bsc#984150).

  - CVE-2014-9839: Theoretical out of bound access in
    magick/colormap-private.h (bsc#984379).

  - CVE-2014-9809: SEGV due to corrupted xwd images.
    (bsc#983799).

  - CVE-2016-5240: SVG converting issue resulting in DoS
    (endless loop) (bsc#983309).

  - CVE-2014-9840: Out of bound access in palm file
    (bsc#984433).

  - CVE-2014-9847: Incorrect handling of 'previous' image in
    the JNG decoder (bsc#984144).

  - CVE-2016-5241: Arithmetic exception (div by 0) in SVG
    conversion (bsc#983455).

  - CVE-2014-9845: Crash due to corrupted dib file
    (bsc#984394).

  - CVE-2014-9844: Out of bound issue in rle file
    (bsc#984373).

  - CVE-2014-9835: Heap overflow in wpf file (bsc#984145).

  - CVE-2014-9829: Out of bound access in sun file
    (bsc#984409).

  - CVE-2014-9846: Added checks to prevent overflow in rle
    file (bsc#983521).

  - CVE-2016-2317: Multiple vulnerabilities when parsing and
    processing SVG files (bsc#965853).

  - CVE-2016-2318: Multiple vulnerabilities when parsing and
    processing SVG files (bsc#965853)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984379"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985442"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected GraphicsMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-Q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-Q16-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick-Q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick-Q16-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick3-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagickWand-Q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagickWand-Q16-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-GraphicsMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.2", reference:"GraphicsMagick-1.3.20-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"GraphicsMagick-debuginfo-1.3.20-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"GraphicsMagick-debugsource-1.3.20-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"GraphicsMagick-devel-1.3.20-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libGraphicsMagick++-Q16-3-1.3.20-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libGraphicsMagick++-Q16-3-debuginfo-1.3.20-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libGraphicsMagick++-devel-1.3.20-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libGraphicsMagick-Q16-3-1.3.20-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libGraphicsMagick-Q16-3-debuginfo-1.3.20-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libGraphicsMagick3-config-1.3.20-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libGraphicsMagickWand-Q16-2-1.3.20-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libGraphicsMagickWand-Q16-2-debuginfo-1.3.20-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-GraphicsMagick-1.3.20-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-GraphicsMagick-debuginfo-1.3.20-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GraphicsMagick / GraphicsMagick-debuginfo / etc");
}
