#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-70.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96400);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/02/28 14:42:19 $");

  script_cve_id("CVE-2016-8654", "CVE-2016-9395", "CVE-2016-9398", "CVE-2016-9560", "CVE-2016-9591");

  script_name(english:"openSUSE Security Update : jasper (openSUSE-2017-70)");
  script_summary(english:"Check for the openSUSE-2017-70 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for jasper fixes the following issues :

  - CVE-2016-8654: Heap-based buffer overflow in QMFB code
    in JPC codec. (bsc#1012530)

  - CVE-2016-9395: Invalid jasper files could lead to abort
    of the library caused by attacker provided image.
    (bsc#1010977)

  - CVE-2016-9398: Invalid jasper files could lead to abort
    of the library caused by attacker provided image.
    (bsc#1010979)

  - CVE-2016-9560: Stack-based buffer overflow in
    jpc_tsfb_getbands2. (bsc#1011830)

  - CVE-2016-9591: Use-after-free on heap in
    jas_matrix_destroy. (bsc#1015993)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015993"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jasper packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/11");
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

if ( rpm_check(release:"SUSE42.1", reference:"jasper-1.900.14-170.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"jasper-debuginfo-1.900.14-170.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"jasper-debugsource-1.900.14-170.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libjasper-devel-1.900.14-170.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libjasper1-1.900.14-170.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libjasper1-debuginfo-1.900.14-170.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libjasper1-32bit-1.900.14-170.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libjasper1-debuginfo-32bit-1.900.14-170.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"jasper-1.900.14-170.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"jasper-debuginfo-1.900.14-170.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"jasper-debugsource-1.900.14-170.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libjasper-devel-1.900.14-170.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libjasper1-1.900.14-170.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libjasper1-debuginfo-1.900.14-170.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libjasper1-32bit-1.900.14-170.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libjasper1-debuginfo-32bit-1.900.14-170.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jasper / jasper-debuginfo / jasper-debugsource / libjasper-devel / etc");
}
