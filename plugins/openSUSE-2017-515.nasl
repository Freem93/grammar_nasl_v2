#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-515.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99704);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/27 13:33:46 $");

  script_cve_id("CVE-2016-10266", "CVE-2016-10267", "CVE-2016-10268", "CVE-2016-10269", "CVE-2016-10270", "CVE-2016-10271", "CVE-2016-10272");

  script_name(english:"openSUSE Security Update : tiff (openSUSE-2017-515)");
  script_summary(english:"Check for the openSUSE-2017-515 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tiff fixes the following issues :

Security issues fixed :

  - CVE-2016-10272: LibTIFF 4.0.7 allows remote attackers to
    cause a denial of service (heap-based buffer overflow)
    or possibly have unspecified other impact via a crafted
    TIFF image, related to 'WRITE of size 2048' and
    libtiff/tif_next.c:64:9 (bsc#1031247).

  - CVE-2016-10271: tools/tiffcrop.c in LibTIFF 4.0.7 allows
    remote attackers to cause a denial of service
    (heap-based buffer over-read and buffer overflow) or
    possibly have unspecified other impact via a crafted
    TIFF image, related to 'READ of size 1' and
    libtiff/tif_fax3.c:413:13 (bsc#1031249).

  - CVE-2016-10270: LibTIFF 4.0.7 allows remote attackers to
    cause a denial of service (heap-based buffer over-read)
    or possibly have unspecified other impact via a crafted
    TIFF image, related to 'READ of size 8' and
    libtiff/tif_read.c:523:22 (bsc#1031250).

  - CVE-2016-10269: LibTIFF 4.0.7 allows remote attackers to
    cause a denial of service (heap-based buffer over-read)
    or possibly have unspecified other impact via a crafted
    TIFF image, related to 'READ of size 512' and
    libtiff/tif_unix.c:340:2 (bsc#1031254).

  - CVE-2016-10268: tools/tiffcp.c in LibTIFF 4.0.7 allows
    remote attackers to cause a denial of service (integer
    underflow and heap-based buffer under-read) or possibly
    have unspecified other impact via a crafted TIFF image,
    related to 'READ of size 78490' and
    libtiff/tif_unix.c:115:23 (bsc#1031255).

  - CVE-2016-10267: LibTIFF 4.0.7 allows remote attackers to
    cause a denial of service (divide-by-zero error and
    application crash) via a crafted TIFF image, related to
    libtiff/tif_ojpeg.c:816:8 (bsc#1031262).

  - CVE-2016-10266: LibTIFF 4.0.7 allows remote attackers to
    cause a denial of service (divide-by-zero error and
    application crash) via a crafted TIFF image, related to
    libtiff/tif_read.c:351:22. (bsc#1031263).

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031263"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tiff packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/27");
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

if ( rpm_check(release:"SUSE42.1", reference:"libtiff-devel-4.0.7-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtiff5-4.0.7-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtiff5-debuginfo-4.0.7-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tiff-4.0.7-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tiff-debuginfo-4.0.7-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tiff-debugsource-4.0.7-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtiff-devel-32bit-4.0.7-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtiff5-32bit-4.0.7-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtiff5-debuginfo-32bit-4.0.7-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtiff-devel-4.0.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtiff5-4.0.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtiff5-debuginfo-4.0.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tiff-4.0.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tiff-debuginfo-4.0.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tiff-debugsource-4.0.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libtiff-devel-32bit-4.0.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libtiff5-32bit-4.0.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libtiff5-debuginfo-32bit-4.0.7-17.3.1") ) flag++;

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
