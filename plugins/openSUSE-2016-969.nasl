#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-969.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(92975);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:37:13 $");

  script_cve_id("CVE-2015-8918", "CVE-2015-8919", "CVE-2015-8920", "CVE-2015-8921", "CVE-2015-8922", "CVE-2015-8923", "CVE-2015-8924", "CVE-2015-8925", "CVE-2015-8926", "CVE-2015-8928", "CVE-2015-8929", "CVE-2015-8930", "CVE-2015-8931", "CVE-2015-8932", "CVE-2015-8933", "CVE-2015-8934", "CVE-2016-4300", "CVE-2016-4301", "CVE-2016-4302", "CVE-2016-4809");

  script_name(english:"openSUSE Security Update : libarchive (openSUSE-2016-969)");
  script_summary(english:"Check for the openSUSE-2016-969 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libarchive was updated to fix 20 security issues.

These security issues were fixed :

  - CVE-2015-8918: Overlapping memcpy in CAB parser
    (bsc#985698).

  - CVE-2015-8919: Heap out of bounds read in LHA/LZH parser
    (bsc#985697).

  - CVE-2015-8920: Stack out of bounds read in ar parser
    (bsc#985675).

  - CVE-2015-8921: Global out of bounds read in mtree parser
    (bsc#985682).

  - CVE-2015-8922: NULL pointer access in 7z parser
    (bsc#985685).

  - CVE-2015-8923: Unclear crashes in ZIP parser
    (bsc#985703).

  - CVE-2015-8924: Heap buffer read overflow in tar
    (bsc#985609).

  - CVE-2015-8925: Unclear invalid memory read in mtree
    parser (bsc#985706).

  - CVE-2015-8926: NULL pointer access in RAR parser
    (bsc#985704).

  - CVE-2015-8928: Heap out of bounds read in mtree parser
    (bsc#985679).

  - CVE-2015-8929: Memory leak in tar parser (bsc#985669).

  - CVE-2015-8930: Endless loop in ISO parser (bsc#985700).

  - CVE-2015-8931: Undefined behavior / signed integer
    overflow in mtree parser (bsc#985689).

  - CVE-2015-8932: Compress handler left shifting larger
    than int size (bsc#985665).

  - CVE-2015-8933: Undefined behavior / signed integer
    overflow in TAR parser (bsc#985688).

  - CVE-2015-8934: Out of bounds read in RAR (bsc#985673).

  - CVE-2016-4300: Heap buffer overflow vulnerability in the
    7zip read_SubStreamsInfo (bsc#985832).

  - CVE-2016-4301: Stack-based buffer overflow in the mtree
    parse_device (bsc#985826).

  - CVE-2016-4302: Heap buffer overflow in the Rar
    decompression functionality (bsc#985835).

  - CVE-2016-4809: Memory allocate error with symbolic links
    in cpio archives (bsc#984990).

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985835"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libarchive packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bsdtar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bsdtar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libarchive-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libarchive-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libarchive13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libarchive13-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libarchive13-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libarchive13-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/16");
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

if ( rpm_check(release:"SUSE42.1", reference:"bsdtar-3.1.2-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"bsdtar-debuginfo-3.1.2-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libarchive-debugsource-3.1.2-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libarchive-devel-3.1.2-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libarchive13-3.1.2-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libarchive13-debuginfo-3.1.2-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libarchive13-32bit-3.1.2-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libarchive13-debuginfo-32bit-3.1.2-13.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bsdtar / bsdtar-debuginfo / libarchive-debugsource / etc");
}
