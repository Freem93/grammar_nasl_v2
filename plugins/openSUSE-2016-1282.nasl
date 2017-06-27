#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1282.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94754);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/24 14:51:33 $");

  script_cve_id("CVE-2014-9907", "CVE-2015-8957", "CVE-2015-8958", "CVE-2015-8959", "CVE-2016-6823", "CVE-2016-7101", "CVE-2016-7513", "CVE-2016-7514", "CVE-2016-7515", "CVE-2016-7516", "CVE-2016-7517", "CVE-2016-7518", "CVE-2016-7519", "CVE-2016-7520", "CVE-2016-7521", "CVE-2016-7522", "CVE-2016-7523", "CVE-2016-7524", "CVE-2016-7525", "CVE-2016-7526", "CVE-2016-7527", "CVE-2016-7528", "CVE-2016-7529", "CVE-2016-7530", "CVE-2016-7531", "CVE-2016-7532", "CVE-2016-7533", "CVE-2016-7534", "CVE-2016-7535", "CVE-2016-7537", "CVE-2016-7538", "CVE-2016-7539", "CVE-2016-7540", "CVE-2016-7799", "CVE-2016-7800", "CVE-2016-7996", "CVE-2016-7997", "CVE-2016-8677", "CVE-2016-8682", "CVE-2016-8683", "CVE-2016-8684");

  script_name(english:"openSUSE Security Update : ImageMagick (openSUSE-2016-1282)");
  script_summary(english:"Check for the openSUSE-2016-1282 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ImageMagick fixes the following issues: These
vulnerabilities could be triggered by processing specially crafted
image files, which could lead to a process crash or resource
consumtion, or potentially have unspecified futher impact.

  - CVE-2016-8684: Mismatch between real filesize and header
    values (bsc#1005123)

  - CVE-2016-8683: Check that filesize is reasonable
    compared to the header value (bsc#1005127)

  - CVE-2016-8682: Stack-buffer read overflow while reading
    SCT header (bsc#1005125)

  - CVE-2016-8677: Memory allocation failure in
    AcquireQuantumPixels (bsc#1005328)

  - CVE-2016-7996, CVE-2016-7997: WPG Reader Issues
    (bsc#1003629)

  - CVE-2016-7800: 8BIM/8BIMW unsigned underflow leads to
    heap overflow (bsc#1002422)

  - CVE-2016-7799: mogrify global buffer overflow
    (bsc#1002421)

  - CVE-2016-7540: writing to RGF format aborts
    (bsc#1000394)

  - CVE-2016-7539: Potential DOS by not releasing memory
    (bsc#1000715)

  - CVE-2016-7538: SIGABRT for corrupted pdb file
    (bsc#1000712)

  - CVE-2016-7537: Out of bound access for corrupted pdb
    file (bsc#1000711)

  - CVE-2016-7535: Out of bound access for corrupted psd
    file (bsc#1000709)

  - CVE-2016-7534: Out of bound access in generic decoder
    (bsc#1000708)

  - CVE-2016-7533: Wpg file out of bound for corrupted file
    (bsc#1000707)

  - CVE-2016-7532: fix handling of corrupted psd file
    (bsc#1000706)

  - CVE-2016-7531: Pbd file out of bound access
    (bsc#1000704)

  - CVE-2016-7530: Out of bound in quantum handling
    (bsc#1000703)

  - CVE-2016-7529: Out-of-bound in quantum handling
    (bsc#1000399)

  - CVE-2016-7528: Out-of-bound access in xcf file coder
    (bsc#1000434)

  - CVE-2016-7527: Out-of-bound access in wpg file coder:
    (bsc#1000436)

  - CVE-2016-7526: out-of-bounds write in
    ./MagickCore/pixel-accessor.h (bsc#1000702)

  - CVE-2016-7525: Heap buffer overflow in psd file coder
    (bsc#1000701)

  - CVE-2016-7524: AddressSanitizer:heap-buffer-overflow
    READ of size 1 in meta.c:465 (bsc#1000700)

  - CVE-2016-7523: AddressSanitizer:heap-buffer-overflow
    READ of size 1 meta.c:496 (bsc#1000699)

  - CVE-2016-7522: Out of bound access for malformed psd
    file (bsc#1000698)

  - CVE-2016-7521: Heap buffer overflow in psd file handling
    (bsc#1000697)

  - CVE-2016-7520: Heap overflow in hdr file handling
    (bsc#1000696)

  - CVE-2016-7519: Out-of-bounds read in coders/rle.c
    (bsc#1000695)

  - CVE-2016-7518: Out-of-bounds read in coders/sun.c
    (bsc#1000694)

  - CVE-2016-7517: Out-of-bounds read in coders/pict.c
    (bsc#1000693)

  - CVE-2016-7516: Out-of-bounds problem in rle, pict, viff
    and sun files (bsc#1000692)

  - CVE-2016-7515: Rle file handling for corrupted file
    (bsc#1000689)

  - CVE-2016-7514: Out-of-bounds read in coders/psd.c
    (bsc#1000688)

  - CVE-2016-7513: Off-by-one error leading to segfault
    (bsc#1000686)

  - CVE-2016-7101: raphicsMagick: SGI Coder Out-Of-Bounds
    Read Vulnerability (bsc#1001221)

  - CVE-2016-6823: raphicsMagick: BMP Coder Out-Of-Bounds
    Write Vulnerability (bsc#1001066)

  - CVE-2015-8959: dOS due to corrupted DDS files
    (bsc#1000713)

  - CVE-2015-8958: Potential DOS in sun file handling due to
    malformed files (bsc#1000691)

  - CVE-2015-8957: Buffer overflow in sun file handling
    (bsc#1000690)

  - CVE-2014-9907: DOS due to corrupted DDS files
    (bsc#1000714)

  - Buffer overflows in SIXEL, PDB, MAP, and TIFF coders
    (bsc#1002209)

  - Divide by zero in WriteTIFFImage (bsc#1002206)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005328"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/14");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"ImageMagick-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ImageMagick-debuginfo-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ImageMagick-debugsource-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ImageMagick-devel-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ImageMagick-extra-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ImageMagick-extra-debuginfo-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libMagick++-6_Q16-3-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libMagick++-6_Q16-3-debuginfo-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libMagick++-devel-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libMagickCore-6_Q16-1-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libMagickWand-6_Q16-1-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"perl-PerlMagick-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"perl-PerlMagick-debuginfo-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"ImageMagick-devel-32bit-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libMagick++-6_Q16-3-32bit-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libMagick++-6_Q16-3-debuginfo-32bit-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libMagick++-devel-32bit-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-32bit-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-32bit-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-32bit-6.8.8.1-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-debuginfo-32bit-6.8.8.1-21.1") ) flag++;

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
