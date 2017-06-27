#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-840.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91967);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/05 16:04:17 $");

  script_cve_id("CVE-2014-9805", "CVE-2014-9806", "CVE-2014-9807", "CVE-2014-9808", "CVE-2014-9809", "CVE-2014-9810", "CVE-2014-9811", "CVE-2014-9812", "CVE-2014-9813", "CVE-2014-9814", "CVE-2014-9815", "CVE-2014-9816", "CVE-2014-9817", "CVE-2014-9818", "CVE-2014-9819", "CVE-2014-9820", "CVE-2014-9821", "CVE-2014-9822", "CVE-2014-9823", "CVE-2014-9824", "CVE-2014-9825", "CVE-2014-9826", "CVE-2014-9828", "CVE-2014-9829", "CVE-2014-9830", "CVE-2014-9831", "CVE-2014-9832", "CVE-2014-9833", "CVE-2014-9834", "CVE-2014-9835", "CVE-2014-9836", "CVE-2014-9837", "CVE-2014-9838", "CVE-2014-9839", "CVE-2014-9840", "CVE-2014-9841", "CVE-2014-9842", "CVE-2014-9843", "CVE-2014-9844", "CVE-2014-9845", "CVE-2014-9846", "CVE-2014-9847", "CVE-2014-9848", "CVE-2014-9849", "CVE-2014-9850", "CVE-2014-9851", "CVE-2014-9852", "CVE-2014-9853", "CVE-2014-9854", "CVE-2015-8894", "CVE-2015-8895", "CVE-2015-8896", "CVE-2015-8897", "CVE-2015-8898", "CVE-2015-8900", "CVE-2015-8901", "CVE-2015-8902", "CVE-2015-8903", "CVE-2016-4562", "CVE-2016-4563", "CVE-2016-4564", "CVE-2016-5687", "CVE-2016-5688", "CVE-2016-5689", "CVE-2016-5690", "CVE-2016-5691", "CVE-2016-5841", "CVE-2016-5842");

  script_name(english:"openSUSE Security Update : ImageMagick (openSUSE-2016-840)");
  script_summary(english:"Check for the openSUSE-2016-840 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ImageMagick was updated to fix 66 security issues.

These security issues were fixed :

  - CVE-2014-9810: SEGV in dpx file handler (bsc#983803).

  - CVE-2014-9811: Crash in xwd file handler (bsc#984032).

  - CVE-2014-9812: NULL pointer dereference in ps file
    handling (bsc#984137).

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

  - CVE-2014-9850: Incorrect thread limit logic
    (bsc#984149).

  - CVE-2014-9851: Crash when parsing resource block
    (bsc#984160).

  - CVE-2014-9852: Incorrect usage of object after it has
    been destroyed (bsc#984191).

  - CVE-2014-9853: Memory leak in rle file handling
    (bsc#984408).

  - CVE-2015-8902: PDB file DoS (CPU consumption)
    (bsc#983253).

  - CVE-2015-8903: Denial of service (cpu) in vicar
    (bsc#983259).

  - CVE-2015-8900: HDR file DoS (endless loop) (bsc#983232).

  - CVE-2015-8901: MIFF file DoS (endless loop)
    (bsc#983234).

  - CVE-2016-5688: Various invalid memory reads in
    ImageMagick WPG (bsc#985442).

  - CVE-2014-9834: Heap overflow in pict file (bsc#984436).

  - CVE-2014-9806: Leaked file descriptor due to corrupted
    file (bsc#983774).

  - CVE-2016-5687: Out of bounds read in DDS coder
    (bsc#985448).

  - CVE-2014-9838: Out of memory crash in magick/cache.c
    (bsc#984370).

  - CVE-2014-9854: Filling memory during identification of
    TIFF image (bsc#984184).

  - CVE-2015-8898: Prevent NULL pointer access in
    magick/constitute.c (bsc#983746).

  - CVE-2014-9833: Heap overflow in psd file (bsc#984406).

  - CVE-2015-8894: Double free in coders/tga.c:221
    (bsc#983523).

  - CVE-2015-8895: Integer and Buffer overflow in
    coders/icon.c (bsc#983527).

  - CVE-2015-8896: Double free / integer truncation issue in
    coders/pict.c:2000 (bsc#983533).

  - CVE-2015-8897: Out of bounds error in SpliceImage
    (bsc#983739).

  - CVE-2016-5690: Bad foor loop in DCM coder (bsc#985451).

  - CVE-2016-5691: Checks for pixel.red/green/blue in dcm
    coder (bsc#985456).

  - CVE-2014-9836: Crash in xpm file handling (bsc#984023).

  - CVE-2014-9808: SEGV due to corrupted dpc images
    (bsc#983796).

  - CVE-2014-9821: Avoid heap overflow in pnm files
    (bsc#984014).

  - CVE-2014-9820: Heap overflow in xpm files (bsc#984150).

  - CVE-2014-9823: Heap overflow in palm file (bsc#984401).

  - CVE-2014-9822: Heap overflow in quantum file
    (bsc#984187).

  - CVE-2014-9825: Heap overflow in corrupted psd file
    (bsc#984427).

  - CVE-2014-9824: Heap overflow in psd file (bsc#984185).

  - CVE-2014-9809: SEGV due to corrupted xwd images
    (bsc#983799).

  - CVE-2014-9826: Incorrect error handling in sun files
    (bsc#984186).

  - CVE-2014-9843: Incorrect boundary checks in
    DecodePSDPixels (bsc#984179).

  - CVE-2014-9842: Memory leak in psd handling (bsc#984374).

  - CVE-2014-9841: Throwing of exceptions in psd handling
    (bsc#984172).

  - CVE-2014-9840: Out of bound access in palm file
    (bsc#984433).

  - CVE-2014-9847: Incorrect handling of 'previous' image in
    the JNG decoder (bsc#984144).

  - CVE-2014-9846: Added checks to prevent overflow in rle
    file (bsc#983521).

  - CVE-2014-9845: Crash due to corrupted dib file
    (bsc#984394).

  - CVE-2014-9844: Out of bound issue in rle file
    (bsc#984373).

  - CVE-2014-9849: Crash in png coder (bsc#984018).

  - CVE-2014-9848: Memory leak in quantum management
    (bsc#984404).

  - CVE-2014-9807: Double free in pdb coder (bsc#983794).

  - CVE-2014-9829: Out of bound access in sun file
    (bsc#984409).

  - CVE-2014-9832: Heap overflow in pcx file (bsc#984183).

  - CVE-2014-9805: SEGV due to a corrupted pnm file
    (bsc#983752).

  - CVE-2016-4564: The DrawImage function in
    MagickCore/draw.c in ImageMagick made an incorrect
    function call in attempting to locate the next token,
    which allowed remote attackers to cause a denial of
    service (buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    file (bsc#983308).

  - CVE-2016-4563: The TraceStrokePolygon function in
    MagickCore/draw.c in ImageMagick mishandled the
    relationship between the BezierQuantum value and certain
    strokes data, which allowed remote attackers to cause a
    denial of service (buffer overflow and application
    crash) or possibly have unspecified other impact via a
    crafted file (bsc#983305).

  - CVE-2016-4562: The DrawDashPolygon function in
    MagickCore/draw.c in ImageMagick mishandled calculations
    of certain vertices integer data, which allowed remote
    attackers to cause a denial of service (buffer overflow
    and application crash) or possibly have unspecified
    other impact via a crafted file (bsc#983292).

  - CVE-2014-9839: Theoretical out of bound access in
    magick/colormap-private.h (bsc#984379).

  - CVE-2016-5689: NULL ptr dereference in dcm coder
    (bsc#985460).

  - CVE-2014-9837: Additional PNM sanity checks
    (bsc#984166).

  - CVE-2014-9835: Heap overflow in wpf file (bsc#984145).

  - CVE-2014-9828: Corrupted (too many colors) psd file
    (bsc#984028).

  - CVE-2016-5841: Out-of-bounds read in
    MagickCore/property.c:1396 could lead to memory leak/
    Integer overflow read to RCE (bnc#986609).

  - CVE-2016-5842: Out-of-bounds read in
    MagickCore/property.c:1396 could lead to memory leak/
    Integer overflow read to RCE (bnc#986608)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983308"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983774"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984023"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984137"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984149"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984370"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984374"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984406"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984427"
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
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986609"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ImageMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/07");
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

if ( rpm_check(release:"SUSE13.2", reference:"ImageMagick-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ImageMagick-debuginfo-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ImageMagick-debugsource-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ImageMagick-devel-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ImageMagick-extra-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ImageMagick-extra-debuginfo-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagick++-6_Q16-5-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagick++-6_Q16-5-debuginfo-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagick++-devel-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagickCore-6_Q16-2-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagickCore-6_Q16-2-debuginfo-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagickWand-6_Q16-2-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libMagickWand-6_Q16-2-debuginfo-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-PerlMagick-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-PerlMagick-debuginfo-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"ImageMagick-devel-32bit-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagick++-6_Q16-5-32bit-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagick++-6_Q16-5-debuginfo-32bit-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagick++-devel-32bit-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagickCore-6_Q16-2-32bit-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagickCore-6_Q16-2-debuginfo-32bit-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagickWand-6_Q16-2-32bit-6.8.9.8-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libMagickWand-6_Q16-2-debuginfo-32bit-6.8.9.8-26.1") ) flag++;

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
