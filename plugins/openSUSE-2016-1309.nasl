#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1309.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94945);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/02/27 15:13:34 $");

  script_cve_id("CVE-2008-3522", "CVE-2014-8158", "CVE-2015-5203", "CVE-2015-5221", "CVE-2016-1577", "CVE-2016-1867", "CVE-2016-2089", "CVE-2016-2116", "CVE-2016-8690", "CVE-2016-8691", "CVE-2016-8692", "CVE-2016-8693", "CVE-2016-8880", "CVE-2016-8881", "CVE-2016-8882", "CVE-2016-8883", "CVE-2016-8884", "CVE-2016-8885", "CVE-2016-8886", "CVE-2016-8887");

  script_name(english:"openSUSE Security Update : jasper (openSUSE-2016-1309)");
  script_summary(english:"Check for the openSUSE-2016-1309 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for jasper to version 1.900.14 fixes several issues.

These security issues were fixed :

  - CVE-2016-8887: NULL pointer dereference in
    jp2_colr_destroy (jp2_cod.c) (bsc#1006836)

  - CVE-2016-8886: memory allocation failure in jas_malloc
    (jas_malloc.c) (bsc#1006599)

  - CVE-2016-8884,CVE-2016-8885: two NULL pointer
    dereferences in bmp_getdata (incomplete fix for
    CVE-2016-8690) (bsc#1007009)

  - CVE-2016-8883: assert in jpc_dec_tiledecode()
    (bsc#1006598)

  - CVE-2016-8882: segfault / NULL pointer access in
    jpc_pi_destroy (bsc#1006597)

  - CVE-2016-8881: Heap overflow in jpc_getuint16()
    (bsc#1006593)

  - CVE-2016-8880: Heap overflow in jpc_dec_cp_setfromcox()
    (bsc#1006591)

  - CVE-2016-8693 Double free vulnerability in mem_close
    (bsc#1005242)

  - CVE-2016-8691, CVE-2016-8692: Divide by zero in
    jpc_dec_process_siz (bsc#1005090)

  - CVE-2016-8690: NULL pointer dereference in bmp_getdata
    triggered by crafted BMP image (bsc#1005084)

  - CVE-2016-2116: Memory leak in the
    jas_iccprof_createfrombuf function in JasPer allowed
    remote attackers to cause a denial of service (memory
    consumption) via a crafted ICC color profile in a JPEG
    2000 image file (bsc#968373) 

  - CVE-2016-2089: invalid read in the JasPer's
    jas_matrix_clip() function (bsc#963983)

  - CVE-2016-1867: Out-of-bounds Read in the JasPer's
    jpc_pi_nextcprl() function (bsc#961886)

  - CVE-2015-5221: Use-after-free (and double-free) in
    Jasper JPEG-200 (bsc#942553).

  - CVE-2015-5203: Double free corruption in JasPer
    JPEG-2000 implementation (bsc#941919)

  - CVE-2008-3522: Buffer overflow in the jas_stream_printf
    function in libjasper/base/jas_stream.c in JasPer might
    have allowed context-dependent attackers to have an
    unknown impact via vectors related to the mif_hdr_put
    function and use of vsprintf (bsc#392410)

  - jasper: NULL pointer dereference in jp2_colr_destroy
    (jp2_cod.c) (incomplete fix for CVE-2016-8887)
    (bsc#1006839)

For additional change description please have a look at the changelog.

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=392410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=941919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=942553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968373"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jasper packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jasper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jasper-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjasper-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjasper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjasper1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjasper1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjasper1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/18");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"jasper-1.900.14-166.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"jasper-debuginfo-1.900.14-166.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"jasper-debugsource-1.900.14-166.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libjasper-devel-1.900.14-166.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libjasper1-1.900.14-166.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libjasper1-debuginfo-1.900.14-166.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libjasper1-32bit-1.900.14-166.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libjasper1-debuginfo-32bit-1.900.14-166.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"jasper-1.900.14-167.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"jasper-debuginfo-1.900.14-167.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"jasper-debugsource-1.900.14-167.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libjasper-devel-1.900.14-167.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libjasper1-1.900.14-167.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libjasper1-debuginfo-1.900.14-167.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libjasper1-32bit-1.900.14-167.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libjasper1-debuginfo-32bit-1.900.14-167.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jasper / jasper-debuginfo / jasper-debugsource / libjasper-devel / etc");
}
