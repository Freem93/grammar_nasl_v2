#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-53.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96378);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/02/13 20:45:10 $");

  script_cve_id("CVE-2014-8127", "CVE-2016-3622", "CVE-2016-3658", "CVE-2016-5321", "CVE-2016-5323", "CVE-2016-5652", "CVE-2016-5875", "CVE-2016-9273", "CVE-2016-9297", "CVE-2016-9448", "CVE-2016-9453");

  script_name(english:"openSUSE Security Update : tiff (openSUSE-2017-53)");
  script_summary(english:"Check for the openSUSE-2017-53 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The tiff library and tools were updated to version 4.0.7 fixing
various bug and security issues.

  - CVE-2014-8127: out-of-bounds read with malformed TIFF
    image in multiple tools [bnc#914890]

  - CVE-2016-9297: tif_dirread.c read outside buffer in
    _TIFFPrintField() [bnc#1010161]

  - CVE-2016-3658: Illegal read in
    TIFFWriteDirectoryTagLongLong8Array function in tiffset
    / tif_dirwrite.c [bnc#974840]

  - CVE-2016-9273: heap overflow [bnc#1010163]

  - CVE-2016-3622: divide By Zero in the tiff2rgba tool
    [bnc#974449]

  - CVE-2016-5652: tiff2pdf JPEG Compression Tables Heap
    Buffer Overflow [bnc#1007280]

  - CVE-2016-9453: out-of-bounds Write memcpy and less bound
    check in tiff2pdf [bnc#1011107]

  - CVE-2016-5875: heap-based buffer overflow when using the
    PixarLog compressionformat [bnc#987351]

  - CVE-2016-9448: regression introduced by fixing
    CVE-2016-9297 [bnc#1011103]

  - CVE-2016-5321: out-of-bounds read in tiffcrop /
    DumpModeDecode() function [bnc#984813]

  - CVE-2016-5323: Divide-by-zero in _TIFFFax3fillruns()
    function (null ptr dereference?) [bnc#984815]

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=914890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987351"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tiff packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/10");
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

if ( rpm_check(release:"SUSE42.1", reference:"libtiff-devel-4.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtiff5-4.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtiff5-debuginfo-4.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tiff-4.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tiff-debuginfo-4.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tiff-debugsource-4.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtiff-devel-32bit-4.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtiff5-32bit-4.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtiff5-debuginfo-32bit-4.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtiff-devel-4.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtiff5-4.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtiff5-debuginfo-4.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tiff-4.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tiff-debuginfo-4.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tiff-debugsource-4.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libtiff-devel-32bit-4.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libtiff5-32bit-4.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libtiff5-debuginfo-32bit-4.0.7-12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff-devel-32bit / libtiff-devel / libtiff5-32bit / libtiff5 / etc");
}
