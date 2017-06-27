#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1230.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94305);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2017/02/09 15:07:54 $");

  script_cve_id("CVE-2015-8957", "CVE-2015-8958", "CVE-2016-5688", "CVE-2016-6823", "CVE-2016-7101", "CVE-2016-7446", "CVE-2016-7447", "CVE-2016-7448", "CVE-2016-7449", "CVE-2016-7515", "CVE-2016-7516", "CVE-2016-7517", "CVE-2016-7519", "CVE-2016-7522", "CVE-2016-7524", "CVE-2016-7526", "CVE-2016-7527", "CVE-2016-7528", "CVE-2016-7529", "CVE-2016-7531", "CVE-2016-7533", "CVE-2016-7537", "CVE-2016-7800", "CVE-2016-7996", "CVE-2016-7997", "CVE-2016-8682", "CVE-2016-8683", "CVE-2016-8684");

  script_name(english:"openSUSE Security Update : GraphicsMagick (openSUSE-2016-1230)");
  script_summary(english:"Check for the openSUSE-2016-1230 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for GraphicsMagick fixes the following issues :

  - CVE-2016-8684: Mismatch between real filesize and header
    values (bsc#1005123)

  - CVE-2016-8683: Check that filesize is reasonable
    compared to the header value (bsc#1005127)

  - CVE-2016-8682: Stack-buffer read overflow while reading
    SCT header (bsc#1005125)

  - CVE-2016-7996, CVE-2016-7997: WPG Reader Issues
    (bsc#1003629)

  - CVE-2016-7800: 8BIM/8BIMW unsigned underflow leads to
    heap overflow (bsc#1002422)

  - CVE-2016-7537: Out of bound access for corrupted pdb
    file (bsc#1000711)

  - CVE-2016-7533: Wpg file out of bound for corrupted file
    (bsc#1000707)

  - CVE-2016-7531: Pbd file out of bound access
    (bsc#1000704)

  - CVE-2016-7529: out of bound in quantum handling
    (bsc#1000399)

  - CVE-2016-7528: Out of bound access in xcf file coder
    (bsc#1000434)

  - CVE-2016-7527: out of bound access in wpg file coder:
    (bsc#1000436)

  - CVE-2016-7526: out-of-bounds write in
    ./MagickCore/pixel-accessor.h (bsc#1000702)

  - CVE-2016-7524: AddressSanitizer:heap-buffer-overflow
    READ of size 1 in meta.c:465 (bsc#1000700)

  - CVE-2016-7522: Out of bound access for malformed psd
    file (bsc#1000698)

  - CVE-2016-7519: out-of-bounds read in coders/rle.c
    (bsc#1000695)

  - CVE-2016-7517: out-of-bounds read in coders/pict.c
    (bsc#1000693)

  - CVE-2016-7516: Out of bounds problem in rle, pict, viff
    and sun files (bsc#1000692)

  - CVE-2016-7515: Rle file handling for corrupted file
    (bsc#1000689)

  - CVE-2016-7446 CVE-2016-7447 CVE-2016-7448 CVE-2016-7449:
    various issues fixed in 1.3.25 (bsc#999673)

  - CVE-2016-7101: SGI Coder Out-Of-Bounds Read
    Vulnerability (bsc#1001221)

  - CVE-2016-6823: BMP Coder Out-Of-Bounds Write
    Vulnerability (bsc#1001066)

  - CVE-2016-5688: Various invalid memory reads in
    ImageMagick WPG (bsc#985442)

  - CVE-2015-8958: Potential DOS in sun file handling due to
    malformed files (bsc#1000691)

  - CVE-2015-8957: Buffer overflow in sun file handling
    (bsc#1000690)

  - Buffer overflows in SIXEL, PDB, MAP, and TIFF coders
    (bsc#1002209)

  - Divide by zero in WriteTIFFImage (bsc#1002206)"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000711"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999673"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected GraphicsMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/27");
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

if ( rpm_check(release:"SUSE13.2", reference:"GraphicsMagick-1.3.20-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"GraphicsMagick-debuginfo-1.3.20-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"GraphicsMagick-debugsource-1.3.20-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"GraphicsMagick-devel-1.3.20-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libGraphicsMagick++-Q16-3-1.3.20-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libGraphicsMagick++-Q16-3-debuginfo-1.3.20-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libGraphicsMagick++-devel-1.3.20-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libGraphicsMagick-Q16-3-1.3.20-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libGraphicsMagick-Q16-3-debuginfo-1.3.20-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libGraphicsMagick3-config-1.3.20-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libGraphicsMagickWand-Q16-2-1.3.20-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libGraphicsMagickWand-Q16-2-debuginfo-1.3.20-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-GraphicsMagick-1.3.20-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-GraphicsMagick-debuginfo-1.3.20-12.1") ) flag++;

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
