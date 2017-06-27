#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-91.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(81141);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2014-3566", "CVE-2014-6585", "CVE-2014-6587", "CVE-2014-6591", "CVE-2014-6593", "CVE-2014-6601", "CVE-2015-0383", "CVE-2015-0395", "CVE-2015-0400", "CVE-2015-0407", "CVE-2015-0408", "CVE-2015-0410", "CVE-2015-0412");

  script_name(english:"openSUSE Security Update : java-1_7_0-openjdk (openSUSE-SU-2015:0190-1) (POODLE)");
  script_summary(english:"Check for the openSUSE-2015-91 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenJDK was updated to 2.5.4 - OpenJDK 7u75 to fix security issues and
bugs :

  - Security fixes

  - S8046656: Update protocol support

  - S8047125, CVE-2015-0395: (ref) More phantom object
    references

  - S8047130: Fewer escapes from escape analysis

  - S8048035, CVE-2015-0400: Ensure proper proxy protocols

  - S8049253: Better GC validation

  - S8050807, CVE-2015-0383: Better performing performance
    data handling

  - S8054367, CVE-2015-0412: More references for endpoints

  - S8055304, CVE-2015-0407: More boxing for
    DirectoryComboBoxModel

  - S8055309, CVE-2015-0408: RMI needs better transportation
    considerations

  - S8055479: TLAB stability

  - S8055489, CVE-2014-6585: Better substitution formats

  - S8056264, CVE-2014-6587: Multicast support improvements

  - S8056276, CVE-2014-6591: Fontmanager feature
    improvements

  - S8057555, CVE-2014-6593: Less cryptic cipher suite
    management

  - S8058982, CVE-2014-6601: Better verification of an
    exceptional invokespecial

  - S8059485, CVE-2015-0410: Resolve parsing ambiguity

  - S8061210, CVE-2014-3566: Issues in TLS"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2015-02/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=914041"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_7_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/24");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-1.7.0.75-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-accessibility-1.7.0.75-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-1.7.0.75-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-debuginfo-1.7.0.75-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-debugsource-1.7.0.75-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-devel-1.7.0.75-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-devel-debuginfo-1.7.0.75-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-headless-1.7.0.75-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-headless-debuginfo-1.7.0.75-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.75-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-debugsource-1.7.0.75-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-demo-1.7.0.75-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.75-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-devel-1.7.0.75-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.75-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-headless-1.7.0.75-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.75-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-javadoc-1.7.0.75-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-src-1.7.0.75-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-openjdk-bootstrap / etc");
}
