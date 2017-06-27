#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-553.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90905);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:11 $");

  script_cve_id("CVE-2016-0686", "CVE-2016-0687", "CVE-2016-0695", "CVE-2016-3425", "CVE-2016-3427");

  script_name(english:"openSUSE Security Update : java-1_7_0-openjdk (openSUSE-2016-553)");
  script_summary(english:"Check for the openSUSE-2016-553 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_7_0-openjdk to version 2.6.6 fixes five
security issues.

These security issues were fixed :

  - CVE-2016-0686: Ensure thread consistency (bsc#976340).

  - CVE-2016-0687: Better byte behavior (bsc#976340).

  - CVE-2016-0695: Make DSA more fair (bsc#976340).

  - CVE-2016-3425: Better buffering of XML strings
    (bsc#976340).

  - CVE-2016-3427: Improve JMX connections (bsc#976340)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=976340"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_7_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/05");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-1.7.0.101-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-accessibility-1.7.0.101-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-1.7.0.101-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-debuginfo-1.7.0.101-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-debugsource-1.7.0.101-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-devel-1.7.0.101-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-devel-debuginfo-1.7.0.101-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-headless-1.7.0.101-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-headless-debuginfo-1.7.0.101-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.101-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-debugsource-1.7.0.101-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-demo-1.7.0.101-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.101-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-devel-1.7.0.101-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.101-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-headless-1.7.0.101-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.101-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-javadoc-1.7.0.101-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-src-1.7.0.101-22.1") ) flag++;

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
