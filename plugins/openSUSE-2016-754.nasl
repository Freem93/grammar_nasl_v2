#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-754.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91772);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2015-7981", "CVE-2015-8126", "CVE-2016-1514", "CVE-2016-1515", "CVE-2016-5108");

  script_name(english:"openSUSE Security Update : vlc (openSUSE-2016-754)");
  script_summary(english:"Check for the openSUSE-2016-754 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for vlc to 2.2.4 to fix the following security issue :

  - CVE-2016-5108: Fix out-of-bound write in adpcm QT IMA
    codec (boo#984382).

This also include an update of codecs and libraries to fix these 3rd
party security issues :

  - CVE-2016-1514: Matroska libebml EbmlUnicodeString Heap
    Information Leak

  - CVE-2016-1515: Matroska libebml Multiple ElementList
    Double Free Vulnerabilities

  - CVE-2015-7981: The png_convert_to_rfc1123 function in
    png.c in libpng allowed remote attackers to obtain
    sensitive process memory information via crafted tIME
    chunk data in an image file, which triggers an
    out-of-bounds read (bsc#952051).

  - CVE-2015-8126: Multiple buffer overflows in the (1)
    png_set_PLTE and (2) png_get_PLTE functions in libpng
    allowed remote attackers to cause a denial of service
    (application crash) or possibly have unspecified other
    impact via a small bit-depth value in an IHDR (aka image
    header) chunk in a PNG image (bsc#954980)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=952051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984382"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected vlc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlc5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlc5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlccore8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlccore8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-noX");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-noX-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-noX-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/23");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libvlc5-2.2.4-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libvlc5-debuginfo-2.2.4-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libvlccore8-2.2.4-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libvlccore8-debuginfo-2.2.4-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"vlc-2.2.4-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"vlc-debuginfo-2.2.4-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"vlc-debugsource-2.2.4-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"vlc-devel-2.2.4-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"vlc-noX-2.2.4-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"vlc-noX-debuginfo-2.2.4-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"vlc-noX-lang-2.2.4-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"vlc-qt-2.2.4-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"vlc-qt-debuginfo-2.2.4-27.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvlc5 / libvlc5-debuginfo / libvlccore8 / libvlccore8-debuginfo / etc");
}
