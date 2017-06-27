#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-742.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86891);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/11/19 15:24:55 $");

  script_cve_id("CVE-2014-9756", "CVE-2015-7805", "CVE-2015-8075");

  script_name(english:"openSUSE Security Update : libsndfile (openSUSE-2015-742)");
  script_summary(english:"Check for the openSUSE-2015-742 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The libsndfile package was updated to fix three security issues :

  - CVE-2015-7805: fix for heap overflow via specially
    crafted AIFF header (bsc#953516)

  - CVE-2015-8075: fix for out of bounds read access in
    function psf_strlcpy_crlf (bsc#953519)

  - CVE-2014-9756: fix a divide-by-zero issue that can lead
    to an DoS (bsc#953521)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=953516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=953519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=953521"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libsndfile packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-progs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-progs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libsndfile-debugsource-1.0.25-17.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsndfile-devel-1.0.25-17.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsndfile-progs-1.0.25-17.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsndfile-progs-debuginfo-1.0.25-17.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsndfile-progs-debugsource-1.0.25-17.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsndfile1-1.0.25-17.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsndfile1-debuginfo-1.0.25-17.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsndfile1-32bit-1.0.25-17.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsndfile1-debuginfo-32bit-1.0.25-17.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsndfile-debugsource-1.0.25-19.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsndfile-devel-1.0.25-19.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsndfile-progs-1.0.25-19.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsndfile-progs-debuginfo-1.0.25-19.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsndfile-progs-debugsource-1.0.25-19.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsndfile1-1.0.25-19.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsndfile1-debuginfo-1.0.25-19.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsndfile1-32bit-1.0.25-19.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsndfile1-debuginfo-32bit-1.0.25-19.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsndfile-progs / libsndfile-progs-debuginfo / etc");
}
